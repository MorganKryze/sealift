package s3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const listXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>user-alice</Name><Prefix>packages/npm/</Prefix><KeyCount>2</KeyCount><MaxKeys>2</MaxKeys>
<IsTruncated>true</IsTruncated>
<Contents><Key>packages/npm/a.tgz</Key><LastModified>2026-11-05T10:20:30.000Z</LastModified>
<ETag>&#34;abc123&#34;</ETag><Size>42</Size><StorageClass>STANDARD</StorageClass></Contents>
<Contents><Key>packages/npm/b c.tgz</Key><LastModified>2026-11-05T11:00:00.000Z</LastModified>
<ETag>&#34;def456&#34;</ETag><Size>7</Size></Contents>
</ListBucketResult>`

func TestList(t *testing.T) {
	ctx := context.Background()
	t.Run("parses a page and sends the query", func(t *testing.T) {
		f := newFake(t, false)
		f.set("list", answer{Status: 200, Body: listXML})
		got, err := f.client(t).List(ctx, "user-alice", "packages/npm/", 5000)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Truncated || len(got.Objects) != 2 {
			t.Fatalf("listing = %+v", got)
		}
		o := got.Objects[0]
		if o.Key != "packages/npm/a.tgz" || o.ETag != `"abc123"` || o.Size != 42 ||
			o.LastModified.UTC().Format("2006-01-02T15:04:05Z") != "2026-11-05T10:20:30Z" {
			t.Errorf("object = %+v", o)
		}
		r := f.requests()[0]
		if r.Path != "/user-alice" || r.Query.Get("prefix") != "packages/npm/" ||
			r.Query.Get("max-keys") != "1000" || r.Query.Get("list-type") != "2" || r.Query.Has("delimiter") {
			t.Errorf("request = %+v", r)
		}
		a := r.Header.Get("Authorization")
		if !strings.Contains(a, "Credential="+testAccess+"/20261106/us-east-1/s3/aws4_request") ||
			r.Header.Get("X-Amz-Content-Sha256") != emptyBodyHash || r.Header.Get("X-Amz-Date") != "20261106T120000Z" {
			t.Errorf("headers = %v", r.Header)
		}
	})
	t.Run("max below 1 is refused", func(t *testing.T) {
		f := newFake(t, false)
		if _, err := f.client(t).List(ctx, "user-alice", "", 0); err == nil || len(f.requests()) != 0 {
			t.Fatalf("err = %v, requests = %d", err, len(f.requests()))
		}
	})
	t.Run("a page over the bound is an error naming it", func(t *testing.T) {
		f := newFake(t, false)
		f.set("list", answer{Status: 200, Body: "<ListBucketResult>" + strings.Repeat("x", MaxListBytes) + "</ListBucketResult>"})
		_, err := f.client(t).List(ctx, "user-alice", "", 10)
		if err == nil || !strings.Contains(err.Error(), "MaxListBytes") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("broken XML is an error", func(t *testing.T) {
		f := newFake(t, false)
		f.set("list", answer{Status: 200, Body: "<ListBucketResult><Contents>"})
		if _, err := f.client(t).List(ctx, "user-alice", "", 10); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestHeadGetDelete(t *testing.T) {
	ctx := context.Background()
	meta := map[string]string{"ETag": `"abc123"`, "Last-Modified": "Wed, 05 Nov 2026 10:20:30 GMT"}

	t.Run("head", func(t *testing.T) {
		f := newFake(t, false)
		f.set("head", answer{Status: 200, Header: map[string]string{
			"ETag": `"abc123"`, "Last-Modified": meta["Last-Modified"], "Content-Length": "5"}})
		o, err := f.client(t).Head(ctx, "user-alice", "packages/npm/a b.tgz")
		if err != nil {
			t.Fatal(err)
		}
		if o.ETag != `"abc123"` || o.Key != "packages/npm/a b.tgz" || o.LastModified.IsZero() {
			t.Errorf("object = %+v", o)
		}
		if r := f.requests()[0]; r.Method != "HEAD" || r.Path != "/user-alice/packages/npm/a%20b.tgz" {
			t.Errorf("request = %+v", r)
		}
	})
	t.Run("get sends If-Match and streams the body", func(t *testing.T) {
		f := newFake(t, false)
		f.set("get", answer{Status: 200, Header: meta, Body: "hello"})
		rc, o, err := f.client(t).Get(ctx, "user-alice", "k", `"abc123"`)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, _ := io.ReadAll(rc)
		if string(b) != "hello" || o.Size != 5 || o.ETag != `"abc123"` {
			t.Errorf("body %q object %+v", b, o)
		}
		if got := f.requests()[0].Header.Get("If-Match"); got != `"abc123"` {
			t.Errorf("If-Match = %q", got)
		}
		if a := f.requests()[0].Header.Get("Authorization"); !strings.Contains(a, "SignedHeaders=host;if-match;x-amz-content-sha256;x-amz-date") {
			t.Errorf("authorization = %s", a)
		}
	})
	t.Run("get without an ETag is refused", func(t *testing.T) {
		f := newFake(t, false)
		if _, _, err := f.client(t).Get(ctx, "user-alice", "k", ""); err == nil || len(f.requests()) != 0 {
			t.Fatalf("err = %v, requests = %d", err, len(f.requests()))
		}
	})
	t.Run("statuses", func(t *testing.T) {
		cases := []struct {
			name   string
			status int
			body   string
			check  func(error) bool
		}{
			{"404 is not found", 404, `<Error><Code>NoSuchKey</Code></Error>`, func(e error) bool { return errors.Is(e, ErrNotFound) }},
			{"412 is changed", 412, `<Error><Code>PreconditionFailed</Code></Error>`, func(e error) bool { return errors.Is(e, ErrChanged) }},
			{"403 is an Error", 403, `<Error><Code>AccessDenied</Code><Message>no</Message></Error>`, func(e error) bool {
				var x *Error
				return errors.As(e, &x) && x.Status == 403 && x.Code == "AccessDenied" && x.Message == "no"
			}},
			{"500 without body", 500, ``, func(e error) bool {
				var x *Error
				return errors.As(e, &x) && x.Status == 500 && x.Code == ""
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := newFake(t, false)
				a := answer{Status: tc.status, Body: tc.body}
				f.set("get", a)
				f.set("head", a)
				f.set("delete", a)
				c := f.client(t)
				if _, _, err := c.Get(ctx, "user-alice", "k", `"e"`); !tc.check(err) {
					t.Errorf("get err = %v", err)
				}
				_, err := c.Head(ctx, "user-alice", "k")
				var he *Error
				switch tc.status {
				case 404:
					if !errors.Is(err, ErrNotFound) {
						t.Errorf("head err = %v", err)
					}
				case 412:
					if !errors.Is(err, ErrChanged) {
						t.Errorf("head err = %v", err)
					}
				default:
					if !errors.As(err, &he) || he.Status != tc.status {
						t.Errorf("head err = %v", err)
					}
				}
				if err := c.Delete(ctx, "user-alice", "k"); !tc.check(err) {
					t.Errorf("delete err = %v", err)
				}
			})
		}
	})
	t.Run("head 404 is not found", func(t *testing.T) {
		f := newFake(t, false)
		f.set("head", answer{Status: 404})
		if _, err := f.client(t).Head(ctx, "user-alice", "k"); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		f := newFake(t, false)
		f.set("delete", answer{Status: 204})
		if err := f.client(t).Delete(ctx, "user-alice", "dir/k"); err != nil {
			t.Fatal(err)
		}
		if r := f.requests()[0]; r.Method != "DELETE" || r.Path != "/user-alice/dir/k" {
			t.Errorf("request = %+v", r)
		}
	})
	t.Run("an answer with no length is refused", func(t *testing.T) {
		f := newFake(t, false)
		f.set("head", answer{Status: 200})
		if _, err := f.client(t).Head(ctx, "user-alice", "k"); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestErrorCleaned(t *testing.T) {
	f := newFake(t, false)
	long := strings.Repeat("é", 500)
	body := "<Error><Code>Odd\x01Code</Code><Message>start\x00\x07\x1b[31m" + long + strings.Repeat("y", 20000) +
		"BEYOND</Message></Error>"
	f.set("list", answer{Status: 400, Body: body})
	c := f.client(t)
	counter := &countingTransport{next: c.hc.Transport}
	c.hc.Transport = counter

	_, err := c.List(context.Background(), "user-alice", "", 10)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v", err)
	}
	if e.Status != 400 || e.Code != "OddCode" {
		t.Errorf("status %d code %q", e.Status, e.Code)
	}
	if n := len([]rune(e.Message)); n != maxMessageChars {
		t.Errorf("message has %d characters", n)
	}
	for _, r := range e.Message {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control character %U in %q", r, e.Message)
		}
	}
	if strings.Contains(e.Message, "BEYOND") {
		t.Error("message reaches past the bound")
	}
	if counter.read > MaxErrorBytes {
		t.Errorf("read %d bytes, bound is %d", counter.read, MaxErrorBytes)
	}
}

type countingTransport struct {
	next http.RoundTripper
	read int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	if err == nil {
		resp.Body = &countingBody{ReadCloser: resp.Body, t: c}
	}
	return resp, err
}

type countingBody struct {
	io.ReadCloser
	t *countingTransport
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.t.read += n
	return n, err
}

func TestNoBucket(t *testing.T) {
	f := newFake(t, false)
	f.set("list", answer{Status: 404, Body: `<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`})
	_, err := f.client(t).List(context.Background(), "user-alice", "", 10)
	if !IsNoBucket(err) {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a missing bucket must not read as a missing key")
	}
	if IsNoBucket(ErrNotFound) || IsNoBucket(nil) {
		t.Error("IsNoBucket is true for other errors")
	}
}

func TestClientRefusesRedirect(t *testing.T) {
	target := newFake(t, false)
	f := newFake(t, false)
	f.set("list", answer{Status: 307, Header: map[string]string{"Location": target.URL + "/user-alice"}})
	_, err := f.client(t).List(context.Background(), "user-alice", "", 10)
	var e *Error
	if !errors.As(err, &e) || e.Status != 307 {
		t.Fatalf("err = %v", err)
	}
	if n := len(target.requests()); n != 0 {
		t.Errorf("the redirect target saw %d requests", n)
	}
}

func TestClientTLS(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, true)
	f.set("list", answer{Status: 200, Body: listXML})

	t.Run("an unknown certificate is refused", func(t *testing.T) {
		_, err := f.client(t).List(ctx, "user-alice", "", 10)
		if err == nil || len(f.requests()) != 0 {
			t.Fatalf("err = %v, requests = %d", err, len(f.requests()))
		}
	})
	t.Run("the CA file makes it trusted", func(t *testing.T) {
		cfg := f.config(t)
		cfg.CAFile = f.caFile(t)
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.List(ctx, "user-alice", "", 10); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the transport has no shortcut", func(t *testing.T) {
		tr := f.client(t).hc.Transport.(*http.Transport)
		if tr.TLSClientConfig.InsecureSkipVerify || tr.Proxy != nil {
			t.Errorf("insecure %v proxy set %v", tr.TLSClientConfig.InsecureSkipVerify, tr.Proxy != nil)
		}
	})
	t.Run("bad CA files", func(t *testing.T) {
		dir := t.TempDir()
		junk := filepath.Join(dir, "junk.pem")
		if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, path := range map[string]string{"missing": filepath.Join(dir, "none.pem"), "no certificate": junk} {
			cfg := f.config(t)
			cfg.CAFile = path
			if _, err := New(cfg); err == nil {
				t.Errorf("%s: no error", name)
			}
		}
	})
}

func TestNewRefusesBadConfig(t *testing.T) {
	f := newFake(t, false)
	cases := map[string]func(*Config){
		"no url":    func(c *Config) { c.URL = nil },
		"scheme":    func(c *Config) { c.URL, _ = url.Parse("ftp://host") },
		"userinfo":  func(c *Config) { c.URL, _ = url.Parse("http://bob:hunter2@host") },
		"query":     func(c *Config) { c.URL, _ = url.Parse("http://host/?a=b") },
		"no access": func(c *Config) { c.AccessKey = nil },
		"no secret": func(c *Config) { c.SecretKey = nil },
	}
	for name, mut := range cases {
		cfg := f.config(t)
		mut(&cfg)
		_, err := New(cfg)
		if err == nil {
			t.Errorf("%s: no error", name)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error echoes the password: %v", name, err)
		}
	}
}

func TestRequestsRefuseBadNames(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, false)
	c := f.client(t)
	badBuckets := []string{"", "ab", "UPPER-case", "has_underscore", "-lead", "trail-", "a..b", strings.Repeat("a", 64), "a/b", "user alice"}
	for _, b := range badBuckets {
		if _, err := c.List(ctx, b, "", 10); err == nil {
			t.Errorf("List accepted bucket %q", b)
		}
		if _, err := c.Head(ctx, b, "k"); err == nil {
			t.Errorf("Head accepted bucket %q", b)
		}
	}
	badKeys := []string{"", strings.Repeat("k", 1025), "bad\xffutf8", "a/../b", "..", "./a", "nul\x00", "line\nbreak"}
	for _, k := range badKeys {
		if _, err := c.Head(ctx, "user-alice", k); err == nil {
			t.Errorf("Head accepted key %q", k)
		}
		if _, _, err := c.Get(ctx, "user-alice", k, `"e"`); err == nil {
			t.Errorf("Get accepted key %q", k)
		}
		if err := c.Delete(ctx, "user-alice", k); err == nil {
			t.Errorf("Delete accepted key %q", k)
		}
	}
	if _, err := c.List(ctx, "user-alice", "bad\xff", 10); err == nil {
		t.Error("List accepted a prefix that is not UTF-8")
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests went out", n)
	}
	f.set("head", answer{Status: 200, Header: map[string]string{"Content-Length": "1"}})
	if _, err := c.Head(ctx, "user-alice", strings.Repeat("k", 1024)); err != nil {
		t.Errorf("a key of 1024 bytes: %v", err)
	}
}

func TestErrorsCarryNoSecret(t *testing.T) {
	ctx := context.Background()
	body := `<Error><Code>Echo</Code><Message>{auth} access=` + testAccess + ` secret=` + testSecret + `</Message></Error>`
	for _, status := range []int{400, 403, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFake(t, false)
			a := answer{Status: status, Body: body, Echo: true}
			f.set("list", a)
			f.set("get", a)
			f.set("delete", a)
			c := f.client(t)
			_, err1 := c.List(ctx, "user-alice", "", 10)
			_, _, err2 := c.Get(ctx, "user-alice", "k", `"e"`)
			err3 := c.Delete(ctx, "user-alice", "k")
			for i, err := range []error{err1, err2, err3} {
				if err == nil {
					t.Fatalf("call %d: no error", i)
				}
				var x *Error
				if !errors.As(err, &x) {
					t.Fatalf("call %d: %v", i, err)
				}
				seen := f.requests()[i].Header.Get("Authorization")
				sig := seen[strings.LastIndex(seen, "Signature=")+len("Signature="):]
				for _, s := range []string{testSecret, testAccess, sig} {
					if strings.Contains(err.Error(), s) || strings.Contains(x.Message, s) || strings.Contains(x.Code, s) {
						t.Errorf("call %d: error holds %q: %v", i, s, err)
					}
				}
			}
		})
	}
	t.Run("transport failure", func(t *testing.T) {
		f := newFake(t, false)
		c := f.client(t)
		f.Close()
		_, err := c.List(ctx, "user-alice", "", 10)
		if err == nil {
			t.Fatal("no error")
		}
		for _, s := range []string{testSecret, testAccess} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("error holds %q: %v", s, err)
			}
		}
	})
	t.Run("a cancelled context stays visible", func(t *testing.T) {
		f := newFake(t, false)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := f.client(t).List(cctx, "user-alice", "", 10)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the keys are copied", func(t *testing.T) {
		f := newFake(t, false)
		cfg := f.config(t)
		c, _ := New(cfg)
		for i := range cfg.SecretKey {
			cfg.SecretKey[i] = 0
		}
		if !bytes.Equal(c.secretKey, []byte(testSecret)) {
			t.Error("the client shares the caller's secret slice")
		}
	})
}
