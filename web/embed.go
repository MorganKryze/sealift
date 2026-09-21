// Package web embeds the built frontend so cmd/sealift can serve it
// alongside the API, with no separate static asset directory to deploy.
package web

import "embed"

// Dist holds the frontend build: dist/index.html and its assets. On a
// fresh clone, before `pnpm -C web run build` runs, dist holds only the
// placeholder committed at dist/index.html.
//
//go:embed dist
var Dist embed.FS
