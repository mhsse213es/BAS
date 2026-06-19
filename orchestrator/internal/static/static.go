// Package static embeds the wwwroot dashboard SPA at compile time and
// exposes an http.Handler for it.
//
// Using a dedicated package lets go:embed resolve the path correctly —
// embed patterns are relative to the Go source file, and this file lives
// in internal/static/ which is two directories above wwwroot at the
// orchestrator root. A sibling directory is required; go:embed does not
// allow ".." traversal.
//
// To reference wwwroot from here, we embed it via ../../wwwroot — but
// that is still forbidden by go:embed. Instead, this package is placed
// in a directory that IS a sibling of wwwroot by creating a symlink, OR
// we put this file at the orchestrator root package.
//
// This file is intentionally placed at orchestrator/internal/static/ and
// uses the path "wwwroot" relative to the orchestrator root by being
// included via the root "staticfs" package below.
package static

import (
	"embed"
	"io/fs"
	"net/http"
)

// FS is the embedded wwwroot directory.
// The embed path is resolved relative to THIS source file.
// Because this file is at orchestrator/internal/static/static.go and
// wwwroot is at orchestrator/wwwroot/, the relative path is ../../wwwroot —
// which go:embed does NOT allow (no ".." traversal).
//
// Resolution: this package is built from a source file that lives at the
// orchestrator module root (not a subdirectory), where "wwwroot" is a
// direct sibling. See orchestrator/staticfs.go (root package) which re-
// exports Handler() for use by cmd/server/main.go.
//
// This file is kept as documentation only. The actual embed is in
// orchestrator/staticfs.go.
var FS embed.FS // placeholder — not used directly

// Handler returns an http.Handler serving files from FS.
func Handler(embeddedFS embed.FS, root string) http.Handler {
	sub, err := fs.Sub(embeddedFS, root)
	if err != nil {
		panic("embedded FS unavailable: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}
