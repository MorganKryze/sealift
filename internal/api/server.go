package api

import (
	"io/fs"
	"net/http"

	"github.com/MorganKryze/sealift/internal/jobs"
	"github.com/MorganKryze/sealift/internal/runner"
	"github.com/MorganKryze/sealift/internal/store"
	"github.com/MorganKryze/sealift/internal/tools"
)

// NewHandlers builds the Handlers every operation of the contract runs
// against.
func NewHandlers(st *store.Store, svc *jobs.Service, tm *tools.Manager, trivy runner.Trivy) *Handlers {
	return &Handlers{
		EventsHandler: &EventsHandler{Jobs: svc},
		Store:         st,
		Service:       svc,
		Tools:         tm,
		Trivy:         trivy,
	}
}

// Routes returns every route this backend serves: the health check
// outside the contract, every operation of api/openapi.yaml mounted at
// base URL /api through the generated strict server, and the frontend
// build in static for every other path. WatchJob (the event stream) is
// one of the contract's operations: Handlers embeds *EventsHandler, so the
// generated dispatch reaches it exactly like any JSON operation.
func Routes(h *Handlers, static fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", HealthHandler)

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
	mux.Handle("/", SPA(static))
	return mux
}
