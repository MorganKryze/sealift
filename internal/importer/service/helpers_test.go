package service

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/importer/token"
)

// fakeVerifier answers from a table; a token it does not know fails the
// signature check, as a forged one would.
type fakeVerifier struct {
	claims map[string]token.Claims
	errs   map[string]error
}

func (f fakeVerifier) Verify(_ context.Context, raw string) (token.Claims, error) {
	if raw == "" {
		return nil, &token.Rejected{Check: "absent"}
	}
	if err, ok := f.errs[raw]; ok {
		return nil, err
	}
	if c, ok := f.claims[raw]; ok {
		return c, nil
	}
	return nil, &token.Rejected{Check: "signature"}
}

// named returns claims that carry the given preferred_username.
func named(name string) token.Claims {
	b, _ := json.Marshal(name)
	return token.Claims{"preferred_username": b}
}

// rig is a service over a fake verifier, with its log kept in a buffer.
type rig struct {
	h    http.Handler
	logs *bytes.Buffer
}

func newRig(t *testing.T, v Verifier, unencrypted ...string) rig {
	t.Helper()
	logs := &bytes.Buffer{}
	h := New(Config{Verifier: v, Unencrypted: unencrypted, Log: slog.New(slog.NewJSONHandler(logs, nil))})
	return rig{h: Routes(h), logs: logs}
}

// get sends GET path with the token header set when tok is not empty.
func (r rig) get(path, tok string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if tok != "" {
		req.Header.Set(TokenHeader, tok)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return r.do(req)
}

func (r rig) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

// problemOf decodes a Problem body and checks its media type.
func problemOf(t *testing.T, rec *httptest.ResponseRecorder) Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	if p.Status != rec.Code {
		t.Errorf("body status %d, response status %d", p.Status, rec.Code)
	}
	return p
}

func detailOf(p Problem) string {
	if p.Detail == nil {
		return ""
	}
	return *p.Detail
}
