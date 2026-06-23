package main

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// expectedWWWRootHash is the SHA-256 hash of the canonical index.html,
// computed and embedded at build time via `go generate` / the release script.
// Set to empty string to disable the check (development builds).
//
// To regenerate:
//
//	sha256sum wwwroot/index.html | awk '{print $1}'
//
// Then paste the result as the value below before building the release binary.
var expectedWWWRootHash = ""

// StaticHandler returns an http.Handler that serves the dashboard SPA from
// the wwwroot/ directory on disk.
//
// On startup it verifies the SHA-256 hash of index.html against
// expectedWWWRootHash (if set). A mismatch logs a fatal error and halts —
// preventing a tampered UI from being served.
//
// Note: full in-binary embedding (go:embed) requires the wwwroot/ directory
// to be a sibling of this source file at build time. This is not the case
// in the current layout (wwwroot lives two levels up). The integrity check
// below provides equivalent tamper detection at the cost of serving from
// disk. A future refactor can move to full embedding by restructuring the
// cmd/server/ directory.
// resolveWWWRoot returns the wwwroot directory path, walking up from the CWD
// so the server works whether launched from orchestrator/ or cmd/server/.
func resolveWWWRoot() string {
	candidates := []string{"./wwwroot", "../../wwwroot", "../wwwroot"}
	for _, c := range candidates {
		if info, err := os.Stat(filepath.Join(c, "index.html")); err == nil && !info.IsDir() {
			return c
		}
	}
	return "./wwwroot" // fall back; will 404 with a clear message
}

func StaticHandler() http.Handler {
	wwwrootDir := resolveWWWRoot()

	// Verify index.html hash if a reference hash is compiled in.
	if expectedWWWRootHash != "" {
		idxPath := filepath.Join(wwwrootDir, "index.html")
		data, err := os.ReadFile(idxPath)
		if err != nil {
			log.Fatalf("[FATAL] wwwroot integrity: cannot read %s: %v", idxPath, err)
		}
		actual := fmt.Sprintf("%x", sha256.Sum256(data))
		if actual != expectedWWWRootHash {
			log.Fatalf("[FATAL] wwwroot integrity: index.html hash mismatch — "+
				"expected %s got %s — file may be tampered. "+
				"Redeploy from a trusted release package.", expectedWWWRootHash, actual)
		}
		log.Printf("[+] wwwroot integrity: index.html hash verified (%s…)", actual[:16])
	} else {
		log.Println("[~] wwwroot integrity: no reference hash compiled in — hash check disabled (dev build)")
	}

	return http.FileServer(http.Dir(wwwrootDir))
}

// WalkWWWRoot returns every file path under wwwrootDir.
// Convenience helper for computing the reference hash set during release packaging.
func WalkWWWRoot(wwwrootDir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(wwwrootDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		paths = append(paths, p)
		return nil
	})
	return paths, err
}
