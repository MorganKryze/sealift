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
// for every other path. WatchJob (the event stream) is one of the
// contract's operations: Handlers embeds *EventsHandler, so the generated
// dispatch reaches it exactly like any JSON operation.
func Routes(h *Handlers, static fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", HealthHandler(h.Ready))
	mux.HandleFunc("GET /livez", LiveHandler)

	strict := NewStrictHandlerWithOptions(h, nil, StrictHTTPServerOptions{
		RequestErrorHandlerFunc: requestError,
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			// The event stream's response starts writing before it can
			// fail, so by the time an error reaches here the status line
			// may already be sent; the log line is the only place left to
			// report it. Every other operation still gets a response.
			logStreamError(r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	})
	contract := &contractRoutes{ServeMux: mux, patterns: map[string]bool{}}
	HandlerWithOptions(strict, StdHTTPServerOptions{BaseRouter: contract, BaseURL: "/api"})

	// Registered after the generated routes above: those exact patterns
	// are more specific and win, so this only catches an /api request the
	// contract does not serve, keeping the SPA fallback below from
	// swallowing it under the frontend shell. /api without its slash
	// reaches it too, through the mux's redirect to /api/.
	mux.HandleFunc("/api/", unrouted(mux, contract.patterns))
	// 0.7.0 documented these routes, so a script may still call them: it
	// learns they are gone and where the answer lives now.
	toolsGone := gone("the tool routes are gone: the server prepares its tools at start, and GET /api/instance reports them")
	mux.HandleFunc("/api/tools", toolsGone)
	mux.HandleFunc("/api/tools/", toolsGone)
	mux.HandleFunc("PUT /api/settings", gone("the settings write is gone: the deployment sets them in its policy file, and GET /api/instance reports them"))
	mux.HandleFunc("/api/signing-key/regenerate", gone("the regenerate route is gone: run sealift signing-key regenerate in the container or pod; GET /api/signing-key reports the key"))
	mux.Handle("/", SPA(static))
	routes := boundBodies(mux)
	if h.Ephemeral > 0 {
		return noStore(routes)
	}
	return routes
}

// contractRoutes records each pattern the generated server registers, so
// a request no route serves can tell a wrong method from an unknown path.
type contractRoutes struct {
	*http.ServeMux
	patterns map[string]bool
}

func (c *contractRoutes) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	c.patterns[pattern] = true
	c.ServeMux.HandleFunc(pattern, handler)
}

// probedMethods fill a 405's Allow header. HEAD matches a GET route, as
// the mux serves it.
var probedMethods = []string{http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodPatch, http.MethodPost, http.MethodPut}

// unrouted answers an /api request no route serves: 405 with an Allow
// header when the path serves other methods of the contract, 404
// otherwise, both as Problem Details. A removed route's method never
// counts as served.
func unrouted(mux *http.ServeMux, contract map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var allow []string
		for _, method := range probedMethods {
			probe := r.Clone(r.Context())
			probe.Method = method
			if _, pattern := mux.Handler(probe); contract[pattern] {
				allow = append(allow, method)
			}
		}
		if len(allow) == 0 {
			WriteProblem(w, NewProblem(http.StatusNotFound, "not found", "no API route serves "+r.URL.Path))
			return
		}
		w.Header().Set("Allow", strings.Join(allow, ", "))
		WriteProblem(w, NewProblem(http.StatusMethodNotAllowed, "method not allowed", r.URL.Path+" does not serve "+r.Method+"; it serves "+strings.Join(allow, ", ")))
	}
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
