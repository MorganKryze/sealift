package service

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/importer/token"
)

const (
	testToken = "test-token.payload.signature"
	testKey   = "test-key"
)

func TestAuthActsForCheckedUser(t *testing.T) {
	var got string
	var calls int
	h := New(Config{Verifier: fakeVerifier{claims: map[string]token.Claims{testToken: named("alice")}}})
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		calls++
		got = userFrom(r.Context())
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(TokenHeader, testToken)
	rec := httptest.NewRecorder()
	h.authenticate(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || calls != 1 || got != "alice" {
		t.Fatalf("status %d, handler calls %d, user %q; want 200, 1, alice", rec.Code, calls, got)
	}

	calls = 0
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(TokenHeader, "forged")
	rec = httptest.NewRecorder()
	h.authenticate(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("forged token: status %d, handler calls %d; want 401, 0", rec.Code, calls)
	}
}

func TestUserFromEmptyContext(t *testing.T) {
	if got := userFrom(context.Background()); got != "" {
		t.Errorf("userFrom = %q, want empty", got)
	}
}

func TestAuthAnswers401(t *testing.T) {
	checks := []string{"absent", "malformed", "algorithm", "key", "signature", "issuer", "audience", "expiry", "not before"}
	errs := map[string]error{}
	for _, c := range checks {
		errs["tok-"+c] = &token.Rejected{Check: c}
	}
	r := newRig(t, fakeVerifier{errs: errs})
	for _, c := range checks {
		t.Run(c, func(t *testing.T) {
			rec := r.get("/api/me", "tok-"+c)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if d := detailOf(problemOf(t, rec)); !strings.Contains(d, c) || strings.Contains(d, "tok-") {
				t.Errorf("detail %q must name %q and hold no token", d, c)
			}
		})
	}
	t.Run("header absent", func(t *testing.T) {
		rec := r.get("/api/me", "")
		if rec.Code != http.StatusUnauthorized || !strings.Contains(detailOf(problemOf(t, rec)), "absent") {
			t.Errorf("status %d, body %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("authorization header is not read", func(t *testing.T) {
		rec := r.get("/api/me", "", "Authorization", "Bearer "+testToken)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestAuthAnswers503(t *testing.T) {
	r := newRig(t, fakeVerifier{errs: map[string]error{
		"t":     &token.Unavailable{Reason: "the key set server did not answer"},
		"other": errors.New("something unforeseen"),
	}})
	rec := r.get("/api/me", "t")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if d := detailOf(problemOf(t, rec)); !strings.Contains(d, "key set") {
		t.Errorf("detail = %q", d)
	}
	rec = r.get("/api/me", "other")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "unforeseen") {
		t.Errorf("status %d body %q: an unforeseen error is a 500 that does not repeat it", rec.Code, rec.Body.String())
	}
}

func TestUserFromClaimOnly(t *testing.T) {
	r := newRig(t, fakeVerifier{claims: map[string]token.Claims{"alice-token": named("alice")}})
	rec := r.get("/api/me", "alice-token",
		"X-Auth-Request-Preferred-Username", "bob",
		"X-Forwarded-User", "bob", "X-Forwarded-Preferred-Username", "bob")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"alice"`) || strings.Contains(rec.Body.String(), "bob") {
		t.Fatalf("status %d body %q, want alice", rec.Code, rec.Body.String())
	}
}

func TestUserNameRefused403(t *testing.T) {
	tests := []struct {
		name   string
		claims token.Claims
	}{
		{"claim absent", token.Claims{"sub": []byte(`"x"`)}},
		{"claim null", token.Claims{"preferred_username": []byte(`null`)}},
		{"claim a number", token.Claims{"preferred_username": []byte(`12`)}},
		{"upper case", named("Alice")},
		{"underscore", named("a_b")},
		{"two dots", named("a..b")},
		{"empty", named("")},
		{"60 characters", named(strings.Repeat("a", 60))},
		{"path", named("../x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, fakeVerifier{claims: map[string]token.Claims{"t": tt.claims}})
			rec := r.get("/api/me", "t")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if d := detailOf(problemOf(t, rec)); !strings.Contains(d, "preferred_username") {
				t.Errorf("detail %q does not name the claim", d)
			}
			if strings.Contains(rec.Body.String(), "Alice") || strings.Contains(rec.Body.String(), "../x") {
				t.Errorf("body repeats the name: %q", rec.Body.String())
			}
		})
	}
}

func TestServiceNeverLeaksCredentials(t *testing.T) {
	r := newRig(t, fakeVerifier{
		claims: map[string]token.Claims{testToken: named("alice"), testToken + "-bad": named("A_B")},
		errs: map[string]error{
			testToken + "-rej": &token.Rejected{Check: "signature"},
			testToken + "-503": &token.Unavailable{Reason: "the key set server did not answer"},
			testToken + "-500": errors.New("failed on " + testToken + " with " + testKey),
		},
	})
	var seen bytes.Buffer
	for _, tok := range []string{testToken, testToken + "-bad", testToken + "-rej", testToken + "-503", testToken + "-500", ""} {
		rec := r.get("/api/me", tok, "Authorization", "Bearer "+testToken)
		seen.Write(rec.Body.Bytes())
		for k, v := range rec.Header() {
			seen.WriteString(k + strings.Join(v, ""))
		}
	}
	seen.Write(r.logs.Bytes())
	for _, secret := range []string{testToken, testKey, "Bearer"} {
		if strings.Contains(seen.String(), secret) {
			t.Errorf("responses or log hold %q", secret)
		}
	}
	if r.logs.Len() == 0 {
		t.Error("nothing was logged: the scan proves nothing")
	}
}

func TestNewWarnsOnUnencryptedKeySet(t *testing.T) {
	r := newRig(t, fakeVerifier{}, "http://idp.example.internal/certs")
	out := r.logs.String()
	if n := strings.Count(out, "\n"); n != 1 || !strings.Contains(out, "http://idp.example.internal/certs") || !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("log = %q, want one warning naming the URL", out)
	}
	if quiet := newRig(t, fakeVerifier{}); quiet.logs.Len() != 0 {
		t.Errorf("a service with nothing unencrypted logged %q", quiet.logs.String())
	}
}
