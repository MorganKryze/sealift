package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/archive"
	"github.com/MorganKryze/sealift/internal/jobs"
)

// captureLog routes the default logger into a buffer for one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// privateKeyForms lists every form the private key's bytes could take in an answer.
func privateKeyForms(t *testing.T, h *Handlers) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.Store.Root(), "private", "signing-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block in the key file")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	seed := parsed.(ed25519.PrivateKey).Seed()
	body := base64.StdEncoding.EncodeToString(block.Bytes)
	return []string{
		"PRIVATE KEY",
		string(seed),
		hex.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(seed),
		base64.URLEncoding.EncodeToString(seed),
		body[24:56],
	}
}

func regenerate(t *testing.T, srv *httptest.Server, mutate func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/signing-key/regenerate", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGetSigningKey(t *testing.T) {
	srv, h := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/signing-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got SigningKey
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := h.Store.SigningKey()
	if got.PublicKeyPem != want.PublicPEM || got.PublicKeySha256 != want.PublicKeySHA256 {
		t.Errorf("answer = %+v, want the store's key %s", got, want.PublicKeySHA256)
	}
	block, _ := pem.Decode([]byte(got.PublicKeyPem))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("publicKeyPem = %q, want a PUBLIC KEY block", got.PublicKeyPem)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKeySha256 != archive.PublicKeySHA256(pub.(ed25519.PublicKey)) {
		t.Error("publicKeySha256 is not the sha256 of the key's DER")
	}
}

func TestRegenerateAnswersTheNewKey(t *testing.T) {
	srv, h := newTestServer(t)
	old := h.Store.SigningKey()
	resp := regenerate(t, srv, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, readBody(t, resp))
	}
	var got SigningKey
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.PublicKeySha256 == old.PublicKeySHA256 {
		t.Error("the answer still names the old key")
	}
	if now := h.Store.SigningKey(); now.PublicKeySHA256 != got.PublicKeySha256 || now.PublicPEM != got.PublicKeyPem {
		t.Errorf("the key in use is %s, the answer named %s", now.PublicKeySHA256, got.PublicKeySha256)
	}
}

func TestRegenerateAnswers500WhenTheKeyCannotBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	srv, h := newTestServer(t)
	old := h.Store.SigningKey()
	private := filepath.Join(h.Store.Root(), "private")
	if err := os.Chmod(private, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })

	resp := regenerate(t, srv, nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want a problem", ct)
	}
	var p Problem
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.Detail == nil || *p.Detail == "" {
		t.Errorf("body %q carries no cause", body)
	}
	if h.Store.SigningKey().PublicKeySHA256 != old.PublicKeySHA256 {
		t.Error("the key in use changed after a failed write")
	}
	for _, bad := range privateKeyForms(t, h) {
		if strings.Contains(body, bad) {
			t.Error("the 500 Problem holds a form of the private key")
		}
	}
}

func TestAnswersNeverHoldThePrivateKey(t *testing.T) {
	srv, h := newTestServer(t)
	// Each answer is checked against the key in use when it was fetched.
	check := func(name, body string) {
		t.Helper()
		if body == "" {
			t.Errorf("%s answered nothing", name)
		}
		for _, bad := range privateKeyForms(t, h) {
			if strings.Contains(body, bad) {
				t.Errorf("%s holds a form of the private key", name)
			}
		}
	}
	get := func(name, path string) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		check(name, readBody(t, resp))
	}
	get("GET signing key", "/api/signing-key")
	get("GET settings", "/api/settings")
	check("POST regenerate", readBody(t, regenerate(t, srv, nil)))
	get("GET settings after regenerate", "/api/settings")
	get("GET signing key after regenerate", "/api/signing-key")
	check("403 Problem", readBody(t, regenerate(t, srv, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })))
}

func TestRegenerateRefusesCrossSite(t *testing.T) {
	const listen = "sealift.lan:8080"
	port := func(srv *httptest.Server) string {
		u, _ := url.Parse(srv.URL)
		return u.Port()
	}
	const (
		otherHost   = "this request is not addressed to this server's own host"
		otherOrigin = "the Origin of this request is not this server's own host"
		otherSite   = "this request comes from another site"
		notJSON     = "the body must be application/json"
	)
	rows := []struct {
		name   string
		mutate func(r *http.Request, port string)
		status int
		check  string // the check a refusal names in the log
		reason string // the detail of the refusal's Problem
	}{
		{"no Origin, JSON", nil, 200, "", ""},
		{"own Origin", func(r *http.Request, p string) { r.Header.Set("Origin", "http://127.0.0.1:"+p) }, 200, "", ""},
		{"localhost Origin on a loopback Host", func(r *http.Request, p string) { r.Header.Set("Origin", "http://localhost:"+p) }, 200, "", ""},
		{"charset on the media type", func(r *http.Request, _ string) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, 200, "", ""},
		{"Sec-Fetch-Site same-origin", func(r *http.Request, _ string) { r.Header.Set("Sec-Fetch-Site", "same-origin") }, 200, "", ""},
		{"Host of the listen address", func(r *http.Request, p string) {
			r.Host = "SEALIFT.lan:" + p
			r.Header.Set("Origin", "http://sealift.lan:"+p)
		}, 200, "", ""},
		{"foreign Origin", func(r *http.Request, _ string) { r.Header.Set("Origin", "http://evil.example") }, 403, "origin", otherOrigin},
		{"null Origin", func(r *http.Request, _ string) { r.Header.Set("Origin", "null") }, 403, "origin", otherOrigin},
		{"foreign Origin on the right port", func(r *http.Request, p string) { r.Header.Set("Origin", "http://evil.example:"+p) }, 403, "origin", otherOrigin},
		{"cross-site fetch", func(r *http.Request, _ string) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403, "fetch-site", otherSite},
		{"text body", func(r *http.Request, _ string) { r.Header.Set("Content-Type", "text/plain") }, 403, "content-type", notJSON},
		{"form body", func(r *http.Request, _ string) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, 403, "content-type", notJSON},
		{"no content type", func(r *http.Request, _ string) { r.Header.Del("Content-Type") }, 403, "content-type", notJSON},
		{"a no-cors text post from another tab", func(r *http.Request, _ string) {
			r.Header.Set("Content-Type", "text/plain")
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, 403, "origin", otherOrigin},
		{"rebinding with Origin", func(r *http.Request, p string) {
			r.Host = "evil.example:" + p
			r.Header.Set("Origin", "http://evil.example:"+p)
		}, 403, "host", otherHost},
		{"rebinding without Origin", func(r *http.Request, p string) { r.Host = "evil.example:" + p }, 403, "host", otherHost},
		{"rebinding to a name that ends like a loopback name", func(r *http.Request, p string) { r.Host = "notlocalhost:" + p }, 403, "host", otherHost},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			q := jobs.NewQueue(nil)
			h := newTestHandlers(t, q)
			t.Cleanup(q.Close)
			h.ListenAddr = listen
			srv := httptest.NewServer(Routes(h, testStatic()))
			t.Cleanup(srv.Close)
			logs := captureLog(t)
			old := h.Store.SigningKey()

			resp := regenerate(t, srv, func(r *http.Request) {
				if row.mutate != nil {
					row.mutate(r, port(srv))
				}
			})
			body := readBody(t, resp)
			if resp.StatusCode != row.status {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, row.status, body)
			}
			now := h.Store.SigningKey()
			if row.status == http.StatusOK {
				if now.PublicKeySHA256 == old.PublicKeySHA256 {
					t.Error("an allowed request did not regenerate the key")
				}
				return
			}
			if now.PublicKeySHA256 != old.PublicKeySHA256 {
				t.Error("a refused request changed the key")
			}
			disk, err := os.ReadFile(filepath.Join(h.Store.Root(), "private", "signing-key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(disk, []byte("PRIVATE KEY")) {
				t.Error("the key file lost its key")
			}
			var p Problem
			if err := json.Unmarshal([]byte(body), &p); err != nil || p.Status != 403 {
				t.Errorf("body %q is not a 403 Problem", body)
			}
			detail := ""
			if p.Detail != nil {
				detail = *p.Detail
			}
			if detail != row.reason {
				t.Errorf("detail = %q, want %q", detail, row.reason)
			}
			if !strings.Contains(logs.String(), `msg="signing key regenerate refused"`) || !strings.Contains(logs.String(), "check="+row.check) {
				t.Errorf("log %q does not name the regenerate and the check %q", logs.String(), row.check)
			}
			for _, leaked := range []string{"evil.example", "notlocalhost", "text/plain", "x-www-form", "cross-site"} {
				if strings.Contains(logs.String(), leaked) || strings.Contains(body, leaked) {
					t.Errorf("the log or the answer repeats a header value: %q", leaked)
				}
			}
		})
	}
}

func TestOtherRoutesAreNotGuardedByTheRegenerateCheck(t *testing.T) {
	srv, _ := newTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/signing-key", nil)
	req.Host = "evil.example"
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status = %d, want 200: the guard covers the regenerate route only", resp.StatusCode)
	}
}
