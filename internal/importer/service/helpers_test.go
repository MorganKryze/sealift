package service

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// safeBuffer is a log buffer the queue's goroutine and the test both touch.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *safeBuffer) Bytes() []byte { return []byte(s.String()) }

func (s *safeBuffer) Len() int { return len(s.String()) }

// rig is a service over a fake verifier, with its log kept in a buffer.
type rig struct {
	h        http.Handler
	handlers *Handlers
	logs     *safeBuffer
}

func newRig(t *testing.T, v Verifier, unencrypted ...string) rig {
	t.Helper()
	return newRigConfig(t, Config{Verifier: v, Unencrypted: unencrypted})
}

// newRigConfig is newRig for a full Config; its Log is the rig's buffer.
func newRigConfig(t *testing.T, cfg Config) rig {
	t.Helper()
	logs := &safeBuffer{}
	cfg.Log = slog.New(slog.NewJSONHandler(logs, nil))
	h := New(cfg)
	return rig{h: Routes(h, testScreens()), handlers: h, logs: logs}
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
