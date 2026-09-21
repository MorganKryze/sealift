package api

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
)

// SPA serves the frontend build from fsys, the "dist" directory stripped of
// its own name. A path that does not name a file in fsys falls back to
// index.html, so a client-side route survives a reload. The fallback reads
// index.html directly instead of routing the rewritten path back through
// http.FileServer, which special-cases that name and would 301-redirect the
// deep link away to "/".
func SPA(fsys fs.FS) http.Handler {
	files := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || name == "." {
			name = "index.html"
		}
		if info, err := fs.Stat(fsys, name); err == nil && !info.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		serveIndex(w, r, fsys)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	f, err := fsys.Open("index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := io.Copy(w, f); err != nil {
		// The response starts writing before a copy failure can surface,
		// so the status line may already be sent; the log line is the
		// only place left to report it.
		slog.ErrorContext(r.Context(), "serving the frontend shell", "path", r.URL.Path, "error", err)
	}
}
