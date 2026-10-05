package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/reporting"
)

// expectedWWWManifestHash is the SHA-256 of wwwroot/MANIFEST.sha256, injected
// by the Docker build (-ldflags -X main.expectedWWWManifestHash=...). The
// manifest lists the SHA-256 of every served file, so this one value anchors
// the whole dashboard (G1c spec section 7). Empty in builds made outside
// Docker: the check is then disabled and logged, as before.
var expectedWWWManifestHash = ""

// StaticHandler returns an http.Handler that serves the dashboard SPA from
// the wwwroot/ directory on disk.
//
// On startup it verifies MANIFEST.sha256 against expectedWWWManifestHash (if
// set), then every file the manifest lists, and rejects any unlisted file. A
// mismatch logs a fatal error and halts -- preventing a tampered UI from
// being served. Hashed /assets/ are served immutable; index.html is no-cache.
//
// Note: full in-binary embedding (go:embed) requires the wwwroot/ directory
// to be a sibling of this source file at build time. This is not the case
// in the current layout (wwwroot lives two levels up). The integrity check
// below provides equivalent tamper detection at the cost of serving from
// disk. A future refactor can move to full embedding by restructuring the
// cmd/server/ directory.
// resolveWWWRoot returns the wwwroot directory path, walking up from the CWD
// so the server works whether launched from orchestrator/ or cmd/server/.
// /wwwroot is checked first because it is the absolute Docker container path
// (bind-mounted by compose). Relative paths are fallbacks for local dev.
func resolveWWWRoot() string {
	candidates := []string{"/wwwroot", "./wwwroot", "../../wwwroot", "../wwwroot"}
	for _, c := range candidates {
		if info, err := os.Stat(filepath.Join(c, "index.html")); err == nil && !info.IsDir() {
			return c
		}
	}
	return "./wwwroot" // fall back; will 404 with a clear message
}

// isDir reports whether path exists and is a directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// resolveScenariosDir returns configured unchanged if it already exists as a
// directory (this is the case in Docker/prod, where SCENARIOS_DIR is always
// set explicitly and bind-mounted). Otherwise it tries a short list of
// fallback candidates relative to the process CWD — chiefly "../scenarios",
// which handles the common `go run ./cmd/server` dev invocation from
// orchestrator/, where the real scenarios/ directory is a sibling of
// orchestrator/, not a child of it (the default "scenarios" only resolves
// correctly when launched from the repo root). If nothing matches, returns
// configured unchanged — identical to today's behavior, so this can never
// make an already-working setup worse.
func resolveScenariosDir(configured string) string {
	if isDir(configured) {
		return configured
	}
	for _, c := range []string{"/scenarios", "./scenarios", "../scenarios", "../../scenarios"} {
		if isDir(c) {
			return c
		}
	}
	return configured
}

func StaticHandler() http.Handler {
	wwwrootDir := resolveWWWRoot()
	reporting.SetWWWRoot(wwwrootDir)

	if expectedWWWManifestHash != "" {
		if err := verifyWWWRoot(wwwrootDir, expectedWWWManifestHash); err != nil {
			log.Fatalf("[FATAL] wwwroot integrity: %v -- files may be tampered. Redeploy from a trusted release package.", err)
		}
		log.Printf("[+] wwwroot integrity: manifest and every listed file verified (%s…)", expectedWWWManifestHash[:16])
	} else {
		log.Println("[~] wwwroot integrity: no reference hash compiled in — hash check disabled (dev build)")
	}
	return cacheHeaders(http.FileServer(http.Dir(wwwrootDir)))
}

const wwwManifestName = "MANIFEST.sha256"

// verifyWWWRoot checks that the manifest matches expected, that every listed
// file exists with its listed hash, and that no unlisted file exists.
func verifyWWWRoot(dir, expected string) error {
	manifestPath := filepath.Join(dir, wwwManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", wwwManifestName, err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != expected {
		return fmt.Errorf("%s hash mismatch: expected %s got %s", wwwManifestName, expected, got)
	}
	listed := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		hash, rel, ok := strings.Cut(line, "  ")
		if !ok || len(hash) != 64 || rel == "" || strings.Contains(rel, "..") {
			return fmt.Errorf("%s: malformed line %q", wwwManifestName, line)
		}
		listed[rel] = hash
	}
	var problems []string
	for rel, want := range listed {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			problems = append(problems, fmt.Sprintf("missing %s", rel))
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			problems = append(problems, fmt.Sprintf("hash mismatch %s", rel))
		}
	}
	walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel != wwwManifestName {
			if _, ok := listed[rel]; !ok {
				problems = append(problems, fmt.Sprintf("unlisted file %s", rel))
			}
		}
		return nil
	})
	if walkErr != nil {
		problems = append(problems, walkErr.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// wwwRootWatchList returns every manifest-listed file plus the manifest, for
// the runtime integrity watcher. Falls back to index.html when there is no
// manifest (dev builds), matching the previous behavior.
func wwwRootWatchList(dir string) []string {
	raw, err := os.ReadFile(filepath.Join(dir, wwwManifestName))
	if err != nil {
		return []string{filepath.Join(dir, "index.html")}
	}
	out := []string{filepath.Join(dir, wwwManifestName)}
	for _, line := range strings.Split(string(raw), "\n") {
		if _, rel, ok := strings.Cut(line, "  "); ok && rel != "" {
			out = append(out, filepath.Join(dir, filepath.FromSlash(rel)))
		}
	}
	return out
}

// cacheHeaders: hashed assets never change under the same name; index.html
// must be revalidated so an upgrade never pairs an old page with a new bundle.
func cacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		h.ServeHTTP(w, r)
	})
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
