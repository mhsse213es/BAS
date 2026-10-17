package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// selfBytes returns the content of the currently running test binary,
// resolving symlinks the same way installSelfBinary must.
func selfBytes(t *testing.T) []byte {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	return data
}

func TestInstallSelfBinary_CopiesRunningExecutable(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "copied-binary")

	if err := installSelfBinary(dest); err != nil {
		t.Fatalf("installSelfBinary: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if !bytes.Equal(got, selfBytes(t)) {
		t.Fatal("copied binary content does not match the running executable")
	}
}

// TestInstallSelfBinary_CreatesMissingParentDir is the regression test for
// the exact failure a fresh macOS host hits: /usr/local/bin does not exist
// by default on a clean install, so a write straight to
// /usr/local/bin/bas-agent fails with "no such file or directory" unless
// the parent directory is created first (mkdir -p semantics).
func TestInstallSelfBinary_CreatesMissingParentDir(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "nosuch-dir", "nested", "bas-agent")

	if err := installSelfBinary(dest); err != nil {
		t.Fatalf("installSelfBinary: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if !bytes.Equal(got, selfBytes(t)) {
		t.Fatal("copied binary content does not match the running executable")
	}
}

func TestInstallSelfBinary_ParentPathBlockedByFile_ReturnsError(t *testing.T) {
	// A destination whose parent path collides with an existing regular
	// file can never be created, no matter how many directories we mkdir -p.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	dest := filepath.Join(blocker, "bas-agent")

	if err := installSelfBinary(dest); err == nil {
		t.Fatal("expected an error when the destination's parent path is blocked by a file, got nil")
	}
}
