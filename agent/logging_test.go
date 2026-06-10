package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenLogFileInWritesAndReopens(t *testing.T) {
	dir := t.TempDir()

	f, err := openLogFileIn(dir)
	if err != nil {
		t.Fatalf("openLogFileIn: %v", err)
	}
	if _, err := f.WriteString("hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	// Reopen (append, not truncate) and add more.
	f2, err := openLogFileIn(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	f2.WriteString("world\n")
	f2.Close()

	data, err := os.ReadFile(filepath.Join(dir, logFileName))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := string(data); !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Errorf("log file lost lines across reopen: %q", got)
	}
}

func TestOpenLogFileInRotatesWhenLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, logFileName)

	// Seed an oversized log file.
	big := make([]byte, maxLogBytes+1)
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	f, err := openLogFileIn(dir)
	if err != nil {
		t.Fatalf("openLogFileIn: %v", err)
	}
	f.Close()

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected rotated %s.1 to exist: %v", logFileName, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Errorf("expected fresh empty %s after rotation, size=%v err=%v", logFileName, fiSize(fi), err)
	}
}

func fiSize(fi os.FileInfo) int64 {
	if fi == nil {
		return -1
	}
	return fi.Size()
}
