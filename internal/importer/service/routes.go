// Package service serves the import role's API behind a token check. It
// wires the token, store and MinIO packages and holds no import logic.
package service

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"

	"github.com/MorganKryze/sealift/internal/importer"
	"github.com/MorganKryze/sealift/internal/importer/token"
	"github.com/MorganKryze/sealift/internal/store/imports"
)

// Verifier checks a raw token and returns its claims.
type Verifier interface {
	Verify(ctx context.Context, raw string) (token.Claims, error)
}

// Config holds what New needs. Unencrypted lists the URLs the service reaches
// without TLS; New warns about each once. UnencryptedLinks names the same
// links (keySet, minio, nexus) for the archive list. A nil MinIO means the
// settings have no minio section. A nil Log discards. Submit queues an
// import's latest attempt and says whether it was taken, which it is not once the queue is closed; Settings and NewPublisher are what an attempt
// publishes with, and ImportVersion is what its report names.
type Config struct {
	Verifier         Verifier
	MinIO            Objects
	Unencrypted      []string
	UnencryptedLinks []string
	Log              *slog.Logger
	Store            *imports.Store
	Submit           func(user, id string) bool
	Settings         importer.Settings
	NewPublisher     func(importer.Settings) (importer.Publisher, error)
	ImportVersion    string
}

// Handlers implement the import contract.
type Handlers struct {
	verifier      Verifier
	objects       Objects
	links         []string
	log           *slog.Logger
	store         *imports.Store
	submit        func(user, id string) bool
	settings      importer.Settings
	newPublisher  func(importer.Settings) (importer.Publisher, error)
	importVersion string
	// startMu makes the duplicate check and the creation of an import one step.
	startMu sync.Mutex
}

// New builds the handlers.
func New(cfg Config) *Handlers {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	for _, u := range cfg.Unencrypted {
		log.Warn("reaching a service over unencrypted http", "url", u)
	}
	return &Handlers{
		verifier: cfg.Verifier, objects: cfg.MinIO, links: cfg.UnencryptedLinks, log: log,
		store: cfg.Store, submit: cfg.Submit, settings: cfg.Settings, newPublisher: cfg.NewPublisher, importVersion: cfg.ImportVersion,
	}
}

// Routes serves GET /healthz, the contract under /api behind the token check,
// the import screens from screens without a token (none when screens is nil),
// and 404 for every other path. Every answer carries the screens' headers.
func Routes(h *Handlers, screens fs.FS) http.Handler {
	mux := http.NewServeMux()
	if screens != nil {
		serveScreens(mux, screens)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{Status: "ok"})
	})
	strict := NewStrictHandlerWithOptions(h, nil, StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeProblem(w, http.StatusBadRequest, "Bad request", "the request could not be read")
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			h.log.Error("a response failed", "error", err)
			writeProblem(w, http.StatusInternalServerError, "Internal error", "the response could not be written")
		},
	})
	// The last middleware is the outermost: the body cap runs before the token
	// check, which runs before the cross-site check.
	HandlerWithOptions(strict, StdHTTPServerOptions{
		BaseRouter: mux, BaseURL: "/api",
		Middlewares:      []MiddlewareFunc{refuseCrossSite, h.authenticate, limitBody},
		ErrorHandlerFunc: badParameter,
	})
	return secure(refuseUnclean(mux))
}

// badParameter answers a malformed parameter with a Problem that repeats none
// of the input; the generated default would echo it as plain text.
func badParameter(w http.ResponseWriter, _ *http.Request, _ error) {
	writeProblem(w, http.StatusBadRequest, "Bad request", "a parameter could not be read")
}
