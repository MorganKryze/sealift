package service

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/MorganKryze/sealift/internal/importer/token"
)

// wantPolicy is written out so a change to the constant fails here.
const wantPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

const testShell = "<!doctype html><html><head><title>screens</title></head></html>"

func testScreens() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    {Data: []byte(testShell)},
		"assets/app.js": {Data: []byte("console.log(1)")},
		"favicon.svg":   {Data: []byte("<svg/>")},
		"secret.txt":    {Data: []byte("not a screen file")},
	}
}

func TestScreensServeOnlyTheirRoutes(t *testing.T) {
	r := newRig(t, fakeVerifier{})
	tests := []struct {
		path     string
		want     int
		wantBody string
		wantType string
	}{
		{"/", 200, "<title>screens</title>", "text/html"},
		{"/imports", 200, "<title>screens</title>", "text/html"},
		{"/imports/20261106T101500Z-3f9a0c1d", 200, "<title>screens</title>", "text/html"},
		{"/instance", 200, "<title>screens</title>", "text/html"},
		{"/import", 200, "<title>screens</title>", "text/html"},
		{"/assets/app.js", 200, "console.log(1)", "javascript"},
		{"/favicon.svg", 200, "<svg/>", "svg"},
		{"/settings", 404, "", ""},
		{"/sessions/x", 404, "", ""},
		{"/sessions/x/review", 404, "", ""},
		{"/imports/x/y", 404, "", ""},
		{"/import/x", 404, "", ""},
		{"/instance/x", 404, "", ""},
		{"/imports/", 404, "", ""},
		{"/index.html", 404, "", ""},
		{"/secret.txt", 404, "", ""},
		{"/assets/", 404, "", ""},
		{"/assets/missing.js", 404, "", ""},
		{"/assets/../x", 404, "", ""},
		{"/assets/../secret.txt", 404, "", ""},
		{"/app/index.html", 404, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := r.get(tt.path, "")
			if rec.Code != tt.want {
				t.Fatalf("GET %s = %d, want %d", tt.path, rec.Code, tt.want)
			}
			if tt.want != 200 {
				return
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body %q lacks %q", rec.Body.String(), tt.wantBody)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tt.wantType) {
				t.Errorf("Content-Type = %q, want it to hold %q", ct, tt.wantType)
			}
		})
	}
}

func TestScreensHeaders(t *testing.T) {
	r := newRig(t, fakeVerifier{claims: map[string]token.Claims{"t": named("alice")}})
	tests := []struct {
		name, path, tok string
		status          int
	}{
		{"shell", "/", "", 200},
		{"asset", "/assets/app.js", "", 200},
		{"health", "/healthz", "", 200},
		{"api", "/api/me", "t", 200},
		{"refused", "/api/me", "", 401},
		{"unknown path", "/settings", "", 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := r.get(tt.path, tt.tok)
			if rec.Code != tt.status {
				t.Fatalf("GET %s = %d, want %d", tt.path, rec.Code, tt.status)
			}
			h := rec.Header()
			if tt.name == "shell" {
				return
			}
			if got := h.Get("Content-Security-Policy"); got != wantPolicy {
				t.Errorf("Content-Security-Policy = %q, want %q", got, wantPolicy)
			}
			if got := h.Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", got)
			}
			if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
	if got := r.get("/", "").Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("the shell's Cache-Control = %q, want no-store", got)
	}
	if got := r.get("/imports", "").Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("the shell at /imports has Cache-Control = %q, want no-store", got)
	}
}

func TestScreensPolicyForbidsFraming(t *testing.T) {
	for _, part := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(ScreensPolicy, part) {
			t.Errorf("the policy lacks %q", part)
		}
	}
}

var nonceMeta = regexp.MustCompile(`<meta name="csp-nonce" content="([A-Za-z0-9+/=]+)">`)

// shellNonce returns the nonce the page's meta tag and its policy name, and
// fails the test when they differ.
func shellNonce(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	m := nonceMeta.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("the shell %q holds no nonce meta tag", rec.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil || len(raw) < 16 {
		t.Fatalf("nonce %q is not base64 of at least 16 bytes", m[1])
	}
	want := strings.Replace(wantPolicy, "style-src 'self'", "style-src 'self' 'nonce-"+m[1]+"'", 1)
	if got := rec.Header().Get("Content-Security-Policy"); got != want {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, want)
	}
	return m[1]
}

func TestShellCarriesAFreshStyleNonce(t *testing.T) {
	r := newRig(t, fakeVerifier{})
	seen := map[string]bool{}
	for _, path := range []string{"/", "/", "/imports", "/imports/20261106T101500Z-3f9a0c1d", "/instance", "/import"} {
		rec := r.get(path, "")
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want the shell never reused", path, got)
		}
		if strings.Contains(rec.Header().Get("Content-Security-Policy"), "unsafe-inline") {
			t.Errorf("GET %s allows unsafe-inline", path)
		}
		n := shellNonce(t, rec)
		if seen[n] {
			t.Errorf("GET %s reused nonce %q", path, n)
		}
		seen[n] = true
	}
	if got := r.get("/assets/app.js", "").Header().Get("Content-Security-Policy"); got != wantPolicy {
		t.Errorf("an asset's policy = %q, want the plain one %q", got, wantPolicy)
	}
}

// countingVerifier fails the test when asked to check a token.
type countingVerifier struct{ calls atomic.Int32 }

func (c *countingVerifier) Verify(context.Context, string) (token.Claims, error) {
	c.calls.Add(1)
	return nil, &token.Rejected{Check: "signature"}
}

func TestScreensNeedNoToken(t *testing.T) {
	v := &countingVerifier{}
	r := newRig(t, v)
	for _, path := range []string{"/", "/imports", "/imports/20261106T101500Z-3f9a0c1d", "/assets/app.js", "/favicon.svg", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if rec := r.do(req); rec.Code != http.StatusOK {
			t.Errorf("GET %s without a token = %d, want 200", path, rec.Code)
		}
	}
	if n := v.calls.Load(); n != 0 {
		t.Errorf("the verifier ran %d times for files that hold no data", n)
	}
	if rec := r.get("/api/me", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/me without a token = %d, want 401", rec.Code)
	}
	if v.calls.Load() != 1 {
		t.Errorf("the API did not reach the verifier")
	}
}

func TestRoutesWithoutScreensServeNone(t *testing.T) {
	h := Routes(New(Config{Verifier: fakeVerifier{}}), nil)
	for _, path := range []string{"/", "/imports", "/assets/app.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("GET %s lacks the headers", path)
		}
	}
}
