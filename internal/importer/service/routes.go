// Package service serves the import role's API behind a token check. It
// wires the token, store and MinIO packages and holds no import logic.
package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/MorganKryze/sealift/internal/importer/token"
)

// Verifier checks a raw token and returns its claims.
type Verifier interface {
	Verify(ctx context.Context, raw string) (token.Claims, error)
}

// Config holds what New needs. Unencrypted lists the URLs the service reaches
// without TLS; New warns about each once. UnencryptedLinks names the same
// links (keySet, minio, nexus) for the archive list. A nil MinIO means the
// settings have no minio section. A nil Log discards.
type Config struct {
	Verifier         Verifier
	MinIO            Objects
	Unencrypted      []string
	UnencryptedLinks []string
	Log              *slog.Logger
}

// Handlers implement the import contract.
type Handlers struct {
	verifier Verifier
	objects  Objects
	links    []string
	log      *slog.Logger
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
	return &Handlers{verifier: cfg.Verifier, objects: cfg.MinIO, links: cfg.UnencryptedLinks, log: log}
}

// Routes serves GET /healthz, the contract under /api behind the token check,
// and 404 for every other path.
func Routes(h *Handlers) http.Handler {
	mux := http.NewServeMux()
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
	// The last middleware is the outermost: the body cap runs before the token check.
	HandlerWithOptions(strict, StdHTTPServerOptions{
		BaseRouter: mux, BaseURL: "/api",
		Middlewares:      []MiddlewareFunc{h.authenticate, limitBody},
		ErrorHandlerFunc: badParameter,
	})
	return mux
}

// badParameter answers a malformed parameter with a Problem that repeats none
// of the input; the generated default would echo it as plain text.
func badParameter(w http.ResponseWriter, _ *http.Request, _ error) {
	writeProblem(w, http.StatusBadRequest, "Bad request", "a parameter could not be read")
}
