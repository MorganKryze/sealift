package service

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/importer/token"
)

func TestRoutesServeOnlyTheImportContract(t *testing.T) {
	r := newRig(t, fakeVerifier{claims: map[string]token.Claims{"t": named("alice")}})
	tests := []struct {
		path string
		tok  string
		want int
	}{
		{"/healthz", "", http.StatusOK},
		{"/api/me", "t", http.StatusOK},
		{"/", "t", http.StatusNotFound},
		{"/settings", "t", http.StatusNotFound},
		{"/sessions/x", "t", http.StatusNotFound},
		{"/api/projects", "t", http.StatusNotFound},
		{"/api/settings", "t", http.StatusNotFound},
		{"/api/tools", "t", http.StatusNotFound},
		{"/api/jobs/current/events", "t", http.StatusNotFound},
		{"/api/projects", "", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.path+" "+tt.tok, func(t *testing.T) {
			if got := r.get(tt.path, tt.tok).Code; got != tt.want {
				t.Errorf("GET %s = %d, want %d", tt.path, got, tt.want)
			}
		})
	}
}

func TestMeNamesTheUser(t *testing.T) {
	r := newRig(t, fakeVerifier{claims: map[string]token.Claims{"t": named("alice")}})
	rec := r.get("/api/me", "t")
	var me Me
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || me.User != "alice" {
		t.Fatalf("body %q: %+v, %v", rec.Body.String(), me, err)
	}
}

func TestBodyAndHeaderBounds(t *testing.T) {
	r := newRig(t, fakeVerifier{claims: map[string]token.Claims{"t": named("alice")}})

	t.Run("declared length over the cap", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", bytes.NewReader(make([]byte, MaxBodyBytes+1)))
		req.Header.Set(TokenHeader, "t")
		rec := r.do(req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		if !strings.Contains(detailOf(problemOf(t, rec)), "65536") {
			t.Errorf("detail %q does not name the cap", rec.Body.String())
		}
	})
	t.Run("declared length at the cap", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", bytes.NewReader(make([]byte, MaxBodyBytes)))
		req.Header.Set(TokenHeader, "t")
		if rec := r.do(req); rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
	t.Run("undeclared length is cut at the cap", func(t *testing.T) {
		var read int
		var readErr error
		h := limitBody(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			n, err := io.Copy(io.Discard, req.Body)
			read, readErr = int(n), err
		}))
		req := httptest.NewRequest(http.MethodPost, "/x", io.MultiReader(bytes.NewReader(make([]byte, MaxBodyBytes+1))))
		req.ContentLength = -1
		h.ServeHTTP(httptest.NewRecorder(), req)
		if readErr == nil || read > MaxBodyBytes {
			t.Errorf("read %d bytes, err %v; want an error at %d", read, readErr, MaxBodyBytes)
		}
	})
}
