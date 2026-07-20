package main

import (
	"os"
	"path/filepath"
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
