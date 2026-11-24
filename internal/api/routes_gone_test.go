package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
)

// A client written for 0.7.0 still calls the tool and settings-write
// routes; it must learn they are gone and where to look instead.
func TestRemovedRoutesAnswerGone(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	srv := httptest.NewServer(Routes(NewHandlers(st, nil, tm), testStatic()))
	t.Cleanup(srv.Close)

	cases := []struct {
		method, path string
		want         []string
	}{
		{"GET", "/api/tools", []string{"GET /api/instance"}},
		{"POST", "/api/tools/trivy/update", []string{"GET /api/instance"}},
		{"POST", "/api/tools/trivy/activate", []string{"GET /api/instance"}},
		{"POST", "/api/tools/trivy/db/update", []string{"GET /api/instance"}},
		{"POST", "/api/tools/uv/install", []string{"GET /api/instance"}},
		{"PUT", "/api/settings", []string{"GET /api/instance", "policy file"}},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusGone {
				t.Fatalf("status = %d, want 410", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
				t.Fatalf("Content-Type = %q, want application/problem+json", ct)
			}
			var p Problem
			if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
				t.Fatal(err)
			}
			if p.Status != http.StatusGone || p.Detail == nil {
				t.Fatalf("problem = %+v, want status 410 with a detail", p)
			}
			for _, w := range c.want {
				if !strings.Contains(*p.Detail, w) {
					t.Errorf("detail %q does not name %q", *p.Detail, w)
				}
			}
		})
	}
}

// The settings read stays: only the write is gone.
func TestSettingsReadSurvivesTheGoneWrite(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tm := tools.NewManager(st, &http.Client{Timeout: time.Second}, nil)
	srv := httptest.NewServer(Routes(NewHandlers(st, nil, tm), testStatic()))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/settings = %d, want 200", resp.StatusCode)
	}
}
