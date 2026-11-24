package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MorganKryze/sealift/internal/tools"
)

type fixedReadiness tools.Readiness

func (r fixedReadiness) State() tools.Readiness { return tools.Readiness(r) }

func healthz(t *testing.T, r Readiness) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	HealthHandler(r)(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	return rec
}

func TestHealthzAnswers503AndNamesWhatIsMissing(t *testing.T) {
	rec := healthz(t, fixedReadiness{Items: []tools.Item{
		{Name: "trivy", Version: "0.55.0", State: tools.ItemReady},
		{Name: "trivy-db", State: tools.ItemFailed, Reason: "connection reset by peer"},
		{Name: "signing-key", Version: "3f9a", State: tools.ItemReady},
		{Name: "pnpm", Version: "10.34.5", State: tools.ItemReady},
		{Name: "uv", Version: "0.13.7", State: tools.ItemPreparing},
	}})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if got, want := strings.TrimSpace(rec.Body.String()), `{"status":"preparing","missing":["trivy-db","uv"]}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

// While the instance prepares, the liveness probe answers 200 and the
// readiness probe 503, on the same server.
func TestLivezAnswers200WhileHealthzAnswers503(t *testing.T) {
	_, h := newTestServer(t)
	h.Ready = fixedReadiness{Items: []tools.Item{{Name: "trivy", State: tools.ItemPreparing}}}
	routes := Routes(h, testStatic())
	for _, c := range []struct {
		path, body string
		code       int
	}{
		{"/livez", `{"status":"ok"}`, http.StatusOK},
		{"/healthz", `{"status":"preparing","missing":["trivy"]}`, http.StatusServiceUnavailable},
	} {
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.code || strings.TrimSpace(rec.Body.String()) != c.body {
			t.Errorf("%s = %d %s, want %d %s", c.path, rec.Code, rec.Body.String(), c.code, c.body)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("%s: Content-Type = %q, want application/json", c.path, got)
		}
	}
}

func TestHealthzAnswers200WhenReady(t *testing.T) {
	rec := healthz(t, fixedReadiness{Ready: true, Warning: "could not refresh the vulnerability database", Items: []tools.Item{
		{Name: "trivy", Version: "0.55.0", State: tools.ItemReady},
		{Name: "trivy-db", Version: "2026-11-02T06:00:00Z", State: tools.ItemReady},
	}})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got, want := strings.TrimSpace(rec.Body.String()), `{"status":"ok"}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}
