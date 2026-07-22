package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withExeAt temporarily overrides os.Executable() by chdir-ing is not
// possible for os.Executable (it reads the real process path), so these
// tests call a small testable seam instead: findWebView2InstallerIn(dir)
// does the glob directly on a given directory, and findWebView2Installer()
// is a one-line wrapper around it using the real executable's directory.
// This keeps the test hermetic (no dependency on where `go test` itself
// happens to run from) without needing to fake os.Executable().
func TestFindWebView2InstallerIn_NoMatch(t *testing.T) {
	dir := t.TempDir()
	if got := findWebView2InstallerIn(dir); got != "" {
		t.Fatalf("no files present: got %q, want empty", got)
	}
}

func TestFindWebView2InstallerIn_OneMatch(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "MicrosoftEdgeWebView2RuntimeInstaller.exe")
	if err := os.WriteFile(want, []byte("stub"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// A non-matching file in the same directory must not interfere.
	if err := os.WriteFile(filepath.Join(dir, "installer.exe"), []byte("stub"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if got := findWebView2InstallerIn(dir); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFindWebView2InstallerIn_RenamedFileStillMatches(t *testing.T) {
	// Confirms the pattern match (not an exact name) — a future Microsoft
	// filename change would still be found here without a code change.
	dir := t.TempDir()
	want := filepath.Join(dir, "EdgeWebView2Setup-RuntimeInstaller-v2.exe")
	if err := os.WriteFile(want, []byte("stub"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if got := findWebView2InstallerIn(dir); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFindWebView2InstallerIn_AmbiguousMatchesReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"MicrosoftEdgeWebView2RuntimeInstaller.exe", "OldWebView2RuntimeInstaller.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stub"), 0644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
	}
	if got := findWebView2InstallerIn(dir); got != "" {
		t.Fatalf("two matches: got %q, want empty (ambiguous match must not guess)", got)
	}
}
