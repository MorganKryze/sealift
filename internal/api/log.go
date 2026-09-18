package api

import (
	"log/slog"
	"net/http"
)

// logStreamError reports a stream that broke after its first byte.
func logStreamError(r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "event stream ended early", "path", r.URL.Path, "error", err)
}
