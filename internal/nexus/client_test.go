package nexus

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testUser     = "sealift-import"
	testPassword = "test-password"
)

func newClient(t *testing.T, srv *httptest.Server, caFile string) *Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{URL: u, Repository: "npm-hosted", User: testUser, Password: []byte(testPassword), CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientErrorsCarryNoCredentials(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testPassword))
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "denied for "+r.Header.Get("Authorization")+" password "+testPassword+" token "+basic)
	}))
	gone := httptest.NewServer(http.NotFoundHandler())
	goneClient := newClient(t, gone, "")
	gone.Close()

	calls := map[string]func(*Client) error{
		"check": func(c *Client) error { return c.CheckRepository(context.Background()) },
		"fetch": func(c *Client) error {
			_, err := c.Fetch(context.Background(), "left-pad", "1.0.0", io.Discard, 1<<20)
			return err
		},
		"upload": func(c *Client) error {
			return c.Upload(context.Background(), "left-pad-1.0.0.tgz", strings.NewReader("x"))
		},
	}
	for name, call := range calls {
		for label, c := range map[string]*Client{"echo": newClient(t, echo, ""), "unreachable": goneClient} {
			err := call(c)
			if err == nil {
				t.Fatalf("%s/%s: no error", name, label)
			}
			for _, secret := range []string{testPassword, basic} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("%s/%s: error holds %q: %v", name, label, secret, err)
				}
			}
		}
	}
	echo.Close()
}

func TestClientRefusesRedirect(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	c := newClient(t, srv, "")

	err := c.CheckRepository(context.Background())
	var ne *Error
	if !asError(err, &ne) || ne.Status != http.StatusFound {
		t.Fatalf("want a 302 Error, got %v", err)
	}
	_, err = c.Fetch(context.Background(), "left-pad", "1.0.0", io.Discard, 10)
	if !asError(err, &ne) || ne.Status != http.StatusFound {
		t.Fatalf("fetch: want a 302 Error, got %v", err)
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("the redirect target saw %d requests", n)
	}
}

func asError(err error, target **Error) bool {
	return errors.As(err, target)
}

func TestClientTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"name":"npm-hosted","format":"npm","type":"hosted"}]`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o600); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)

	t.Run("no CA fails verification", func(t *testing.T) {
		err := newClient(t, srv, "").CheckRepository(context.Background())
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("want a certificate error, got %v", err)
		}
	})
	t.Run("CA file passes", func(t *testing.T) {
		if err := newClient(t, srv, ca).CheckRepository(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing CA file", func(t *testing.T) {
		missing := filepath.Join(dir, "absent.pem")
		_, err := New(Config{URL: u, Repository: "npm-hosted", CAFile: missing})
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("want an error naming %s, got %v", missing, err)
		}
	})
	t.Run("CA file without certificate", func(t *testing.T) {
		_, err := New(Config{URL: u, Repository: "npm-hosted", CAFile: junk})
		if err == nil || !strings.Contains(err.Error(), junk) {
			t.Fatalf("want an error naming %s, got %v", junk, err)
		}
	})
}

func TestClientNew(t *testing.T) {
	good, _ := url.Parse("https://nexus.example.internal")
	ftp, _ := url.Parse("ftp://nexus.example.internal")
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"no url":     {Config{Repository: "r"}, "http or https"},
		"ftp":        {Config{URL: ftp, Repository: "r"}, "http or https"},
		"repository": {Config{URL: good}, "repository is empty"},
	} {
		_, err := New(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}

func TestErrorMessageCleaned(t *testing.T) {
	body := strings.Repeat("ab\x07\ncd\x00", 400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	err := newClient(t, srv, "").CheckRepository(context.Background())
	var ne *Error
	if !asError(err, &ne) || ne.Status != 503 {
		t.Fatalf("want a 503 Error, got %v", err)
	}
	want := strings.Repeat("abcd", 100)[:300]
	if ne.Message != want {
		t.Fatalf("message = %q, want %q", ne.Message, want)
	}
}

func TestClientRepositoryAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"missing":    {`[{"name":"other","format":"npm","type":"hosted"}]`, `"npm-hosted" not found`},
		"wrong form": {`[{"name":"npm-hosted","format":"maven2","type":"hosted"}]`, "maven2 hosted"},
		"wrong type": {`[{"name":"npm-hosted","format":"npm","type":"proxy"}]`, "npm proxy"},
		"not json":   {`<html>`, "not readable"},
		"found":      {`[{"name":"npm-hosted","format":"npm","type":"hosted"}]`, ""},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, tc.body) }))
		err := newClient(t, srv, "").CheckRepository(context.Background())
		srv.Close()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}

func TestFetchLimitAndPath(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		_, _ = io.WriteString(w, strings.Repeat("z", 50))
	}))
	defer srv.Close()
	c := newClient(t, srv, "")
	var sb strings.Builder
	found, err := c.Fetch(context.Background(), "@scope/pkg", "1.2.3", &sb, 50)
	if err != nil || !found || sb.Len() != 50 {
		t.Fatalf("found=%v err=%v len=%d", found, err, sb.Len())
	}
	if got := path.Load(); got != "/repository/npm-hosted/@scope/pkg/-/pkg-1.2.3.tgz" {
		t.Fatalf("path = %v", got)
	}
	if _, err := c.Fetch(context.Background(), "pkg", "1.0.0", io.Discard, 49); err == nil || !strings.Contains(err.Error(), "larger than 49") {
		t.Fatalf("want a limit error, got %v", err)
	}
	if _, err := c.Fetch(context.Background(), "../x", "1.0.0", io.Discard, 49); err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("want a path error, got %v", err)
	}
}

func TestClientIgnoresProxyEnvironment(t *testing.T) {
	tr, ok := newClient(t, httptest.NewServer(http.NotFoundHandler()), "").http.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not an http.Transport")
	}
	// ProxyFromEnvironment reads the environment once per process, so a
	// setenv test would prove nothing.
	if tr.Proxy != nil {
		t.Fatal("the client routes requests through a proxy, which would carry the credentials")
	}
}
