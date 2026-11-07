package service

import (
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// ScreensPolicy limits every load of a page to its own origin and forbids framing.
const ScreensPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// secure sets the headers every answer carries, screens and API alike.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ScreensPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// serveScreens registers the screens' routes on mux. They sit outside the
// token check: the files hold no user data.
func serveScreens(mux *http.ServeMux, screens fs.FS) {
	shell := func(w http.ResponseWriter, r *http.Request) {
		f, err := screens.Open("index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		// The status line is sent by now; a failed copy leaves nothing to report to the client.
		_, _ = io.Copy(w, f)
	}
	mux.HandleFunc("GET /{$}", shell)
	mux.HandleFunc("GET /imports", shell)
	mux.HandleFunc("GET /imports/{id}", shell)

	files := http.FileServerFS(screens)
	mux.HandleFunc("GET /assets/{file...}", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if info, err := fs.Stat(screens, name); err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
	for _, icon := range []string{"/favicon.svg", "/favicon-32.png", "/apple-touch-icon.png"} {
		mux.Handle("GET "+icon, files)
	}
}

// refuseUnclean answers 404 to a path outside /api with a dot segment, where
// the mux would redirect to the cleaned path. The API answers its own errors.
func refuseUnclean(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		for _, seg := range strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/") {
			if seg == "." || seg == ".." {
				http.NotFound(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
