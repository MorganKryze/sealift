// Package web embeds the built frontend so cmd/sealift can serve it
// alongside the API, with no separate static asset directory to deploy.
package web

import (
	"embed"
	"io/fs"
)

// Dist holds the frontend build: dist/app once `pnpm -C web run build` has
// run, and always dist/index.html, the placeholder committed there so a
// fresh clone still builds before that build ever runs. Vite writes to
// dist/app (see web/vite.config.ts's build.outDir), never touching the
// placeholder, so a local build leaves the working tree clean instead of
// dirtying a tracked file every time.
//
//go:embed dist
var Dist embed.FS

// Static returns the frontend to serve: dist/app once it holds a real
// build, else dist itself, whose only file is the placeholder.
func Static() (fs.FS, error) {
	if info, err := fs.Stat(Dist, "dist/app/index.html"); err == nil && !info.IsDir() {
		return fs.Sub(Dist, "dist/app")
	}
	return fs.Sub(Dist, "dist")
}

// ImportScreens returns the import role's screens: dist/import once
// `pnpm -C web run build` has run, else only the placeholder, so the role
// never serves the collection's build that sits beside it in dist.
func ImportScreens() (fs.FS, error) {
	if info, err := fs.Stat(Dist, "dist/import/index.html"); err == nil && !info.IsDir() {
		return fs.Sub(Dist, "dist/import")
	}
	return placeholderOnly{fs.FS(Dist)}, nil
}

// placeholderOnly shows dist/index.html as index.html and nothing else.
type placeholderOnly struct{ dist fs.FS }

func (p placeholderOnly) Open(name string) (fs.File, error) {
	if name != "index.html" {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return p.dist.Open("dist/index.html")
}
