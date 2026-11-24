package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
)

// NewHandlers builds the Handlers every operation of the contract runs
// against, under the default policy.
func NewHandlers(st *store.Store, svc *jobs.Service, tm *tools.Manager) *Handlers {
	return &Handlers{
		EventsHandler: &EventsHandler{Jobs: svc},
		Store:         st,
		Service:       svc,
		Tools:         tm,
		Ready:         toolsReadiness{tm},
		Policy:        policy.Policy{Settings: store.DefaultSettings, Pip: store.DefaultPipTarget, Brand: policy.DefaultBrand(), Review: policy.DefaultReview()},
	}
}

// Routes returns every route this backend serves: the readiness and
// liveness checks at the root, the readiness one answered from h.Ready;
// every other operation of api/openapi.yaml mounted at base URL /api
// through the generated strict server; and the frontend build in static
// for every other path. refuseCrossSite wraps all of it and
// guards the signing key's regenerate route. WatchJob
// (the event stream) is one of the contract's operations: Handlers embeds
// *EventsHandler, so the generated dispatch reaches it exactly like any JSON
// operation.
func Routes(h *Handlers, static fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", HealthHandler(h.Ready))
	mux.HandleFunc("GET /livez", LiveHandler)

	strict := NewStrictHandlerWithOptions(h, nil, StrictHTTPServerOptions{
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			// The event stream's response starts writing before it can
			// fail, so by the time an error reaches here the status line
			// may already be sent; the log line is the only place left to
			// report it. Every other operation still gets a response.
			logStreamError(r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	})
	HandlerWithOptions(strict, StdHTTPServerOptions{BaseRouter: mux, BaseURL: "/api"})

	// Registered after the generated routes above: those exact patterns
	// are more specific and win, so this only catches an /api path the
	// contract does not define, keeping the SPA fallback below from
	// swallowing it under the frontend shell.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	// 0.7.0 documented these routes, so a script may still call them: it
	// learns they are gone and where the answer lives now.
	toolsGone := gone("the tool routes are gone: the server prepares its tools at start, and GET /api/instance reports them")
	mux.HandleFunc("/api/tools", toolsGone)
	mux.HandleFunc("/api/tools/", toolsGone)
	mux.HandleFunc("PUT /api/settings", gone("the settings write is gone: the deployment sets them in its policy file, and GET /api/instance reports them"))
	mux.Handle("/", SPA(static))
	routes := refuseCrossSite(mux, allowedHosts(h.ListenAddr))
	if h.Ephemeral > 0 {
		return noStore(routes)
	}
	return routes
}

// noStore keeps the browser from writing API answers, reports and archives
// included, to its disk cache, where an erase on the server cannot reach.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// gone answers a route a past release served with a 410 naming what
// replaced it.
func gone(detail string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		WriteProblem(w, NewProblem(http.StatusGone, "route removed", detail))
	}
}
