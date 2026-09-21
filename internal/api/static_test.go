package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/MorganKryze/sealift/internal/jobs"
)

// testStatic is a minimal frontend build: an index shell and one asset, so
// a test can tell the SPA fallback apart from a real file.
func testStatic() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("shell")},
		"assets/app.js": &fstest.MapFile{Data: []byte("app")},
	}
}

func TestRoutesSPAFallback(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := Routes(newTestHandlers(t, q), testStatic())

	for _, p := range []string{"/", "/projects", "/projects/abc/analyses/1"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "shell" {
			t.Errorf("%s: status = %d, body = %q, want the index shell", p, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "app" {
		t.Errorf("asset: status = %d, body = %q, want the asset itself", rec.Code, rec.Body.String())
	}
}

func TestRoutesAPINeverShadowed(t *testing.T) {
	q := jobs.NewQueue(nil)
	defer q.Close()
	h := Routes(newTestHandlers(t, q), testStatic())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "shell") {
		t.Error("an unknown /api path returned the SPA shell instead of a 404")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/projects", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/projects: status = %d, want 200", rec.Code)
	}
}
