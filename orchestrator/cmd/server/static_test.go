package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestIsDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	if !isDir(dir) {
		t.Errorf("isDir(%q) = false, want true (real directory)", dir)
	}
	if isDir(file) {
		t.Errorf("isDir(%q) = true, want false (it's a file, not a directory)", file)
	}
	if isDir(filepath.Join(dir, "does-not-exist")) {
		t.Error("isDir(nonexistent path) = true, want false")
	}
}

func TestResolveScenariosDir_ConfiguredExists(t *testing.T) {
	dir := t.TempDir()
	if got := resolveScenariosDir(dir); got != dir {
		t.Errorf("resolveScenariosDir(%q) = %q, want %q (an existing configured dir is always used as-is)", dir, got, dir)
	}
}

// TestResolveScenariosDir_ConfiguredMissing_NoFallbackMatches proves the
// no-op case: when neither the configured path nor any fallback candidate
// exists, the function returns the configured value unchanged (identical to
// today's behavior — scenario.Engine.Load() then fails with its own
// existing, already-logged warning; this function never makes things worse).
// Runs inside a fresh empty tempdir (chdir'd into for the duration of the
// test) so it can't accidentally match this repo's real scenarios/ directory
// via one of the relative fallback candidates.
func TestResolveScenariosDir_ConfiguredMissing_NoFallbackMatches(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	empty := t.TempDir()
	if err := os.Chdir(empty); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer os.Chdir(orig)

	configured := "definitely-does-not-exist"
	if got := resolveScenariosDir(configured); got != configured {
		t.Errorf("resolveScenariosDir(%q) = %q, want %q unchanged (no candidate should exist in an empty tempdir)", configured, got, configured)
	}
}

// TestResolveScenariosDir_FallsBackToParentDir proves the actual fix: when
// the configured path is missing but a "scenarios" directory exists one
// level up from the CWD, it's found and used — the exact topology of `go
// run ./cmd/server` invoked from orchestrator/, where the real scenarios/
// directory is a sibling of orchestrator/, not a child of it.
func TestResolveScenariosDir_FallsBackToParentDir(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	root := t.TempDir()
	scenariosDir := filepath.Join(root, "scenarios")
	if err := os.Mkdir(scenariosDir, 0755); err != nil {
		t.Fatalf("mkdir scenarios: %v", err)
	}
	cwd := filepath.Join(root, "orchestrator")
	if err := os.Mkdir(cwd, 0755); err != nil {
		t.Fatalf("mkdir orchestrator: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer os.Chdir(orig)

	got := resolveScenariosDir("scenarios")
	want := "../scenarios"
	if got != want {
		t.Errorf("resolveScenariosDir(%q) = %q, want %q (sibling scenarios/ one level up)", "scenarios", got, want)
	}
}

// writeWWWRoot builds a wwwroot with a valid MANIFEST.sha256 and returns the
// directory plus the manifest's own SHA-256 (what the binary is built with).
func writeWWWRoot(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	var names []string
	for p, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		names = append(names, p)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, p := range names {
		fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256([]byte(files[p])), p)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.sha256"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, fmt.Sprintf("%x", sha256.Sum256([]byte(b.String())))
}

var sampleWWW = map[string]string{
	"index.html":            "<html></html>",
	"assets/app.ABC123.js":  "console.log(1)",
	"assets/app.DEF456.css": "body{}",
	"images/logo.png":       "png",
}

func TestVerifyWWWRoot_ValidTreePasses(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	if err := verifyWWWRoot(dir, h); err != nil {
		t.Fatalf("verifyWWWRoot = %v, want nil", err)
	}
}

func TestVerifyWWWRoot_TamperedFileFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.WriteFile(filepath.Join(dir, "assets", "app.ABC123.js"), []byte("alert(1)"), 0o644)
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "assets/app.ABC123.js") {
		t.Fatalf("verifyWWWRoot = %v, want a hash mismatch naming the file", err)
	}
}

func TestVerifyWWWRoot_UnlistedFileFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.WriteFile(filepath.Join(dir, "assets", "evil.js"), []byte("x"), 0o644)
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "evil.js") {
		t.Fatalf("verifyWWWRoot = %v, want an unlisted-file error naming evil.js", err)
	}
}

func TestVerifyWWWRoot_MissingFileFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.Remove(filepath.Join(dir, "images", "logo.png"))
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "images/logo.png") {
		t.Fatalf("verifyWWWRoot = %v, want a missing-file error", err)
	}
}

func TestVerifyWWWRoot_EditedManifestFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	f, _ := os.OpenFile(filepath.Join(dir, "MANIFEST.sha256"), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("\n")
	f.Close()
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "MANIFEST.sha256") {
		t.Fatalf("verifyWWWRoot = %v, want a manifest hash mismatch", err)
	}
}

func TestVerifyWWWRoot_MissingManifestFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.Remove(filepath.Join(dir, "MANIFEST.sha256"))
	if err := verifyWWWRoot(dir, h); err == nil {
		t.Fatal("verifyWWWRoot = nil, want an error when MANIFEST.sha256 is missing")
	}
}

func TestWWWRootWatchList_CoversEveryManifestFile(t *testing.T) {
	dir, _ := writeWWWRoot(t, sampleWWW)
	got := wwwRootWatchList(dir)
	if len(got) != len(sampleWWW)+1 {
		t.Fatalf("watch list has %d entries, want %d (every file + the manifest): %v", len(got), len(sampleWWW)+1, got)
	}
}

func TestCacheHeaders(t *testing.T) {
	h := cacheHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for path, want := range map[string]string{
		"/assets/app.ABC123.js": "public, max-age=31536000, immutable",
		"/":                     "no-cache",
		"/index.html":           "no-cache",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s Cache-Control = %q, want %q", path, got, want)
		}
	}
}
