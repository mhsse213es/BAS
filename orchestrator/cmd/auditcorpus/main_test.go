package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomically_HappyPath_WritesExpectedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	err := writeFileAtomically(path, func(w io.Writer) error {
		_, err := w.Write([]byte("real content"))
		return err
	})
	if err != nil {
		t.Fatalf("writeFileAtomically: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != "real content" {
		t.Errorf("content = %q, want %q", got, "real content")
	}
}

func TestWriteFileAtomically_MidWriteFailure_LeavesExistingFileUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("original content"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	writeErr := errors.New("simulated disk-full mid-write")
	err := writeFileAtomically(path, func(w io.Writer) error {
		_, _ = w.Write([]byte("partial garbage"))
		return writeErr
	})
	if !errors.Is(err, writeErr) {
		t.Fatalf("writeFileAtomically error = %v, want %v", err, writeErr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != "original content" {
		t.Errorf("existing file was modified on write failure -- content = %q, want unchanged %q", got, "original content")
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "out.txt" {
			t.Errorf("temp file %q was not cleaned up after failure", e.Name())
		}
	}
}
