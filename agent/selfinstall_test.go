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

func TestInstallSelfBinary_UnwritableDest_ReturnsError(t *testing.T) {
	// A destination inside a nonexistent directory can never be written.
	dest := filepath.Join(t.TempDir(), "nosuch-dir", "bas-agent")
	if err := installSelfBinary(dest); err == nil {
		t.Fatal("expected an error writing into a nonexistent directory, got nil")
	}
}
