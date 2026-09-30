package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// brokenWriter always fails -- stands in for os.Stdout when it's an
// invalid/detached handle, as happens for a Windows service running in
// Session 0 with no console attached.
type brokenWriter struct{}

func (brokenWriter) Write(p []byte) (int, error) {
	return 0, errors.New("simulated: no console attached")
}

// TestTeeWriter_FileSurvivesBrokenConsole is the regression test for the
// bug that made a real Windows-service agent's persistent log file capture
// only its very first line and nothing else -- forever, across months of
// restarts -- while the exact same binary run interactively (a console
// attached) logged everything correctly. io.MultiWriter's Write aborts the
// whole chain the moment any one writer returns an error; when the console
// writer came first in that chain and a service's stdout is broken, the
// file writer behind it in the chain never ran, so every log.Printf after
// initFileLogging's own line was silently lost -- with no error surfaced
// anywhere, because the log package's Output() itself discards the error
// SetOutput's writer returns. This test proves the fix: the file writer
// gets every write regardless of what the console writer does with it.
func TestTeeWriter_FileSurvivesBrokenConsole(t *testing.T) {
	dir := t.TempDir()
	f, err := openLogFileIn(dir)
	if err != nil {
		t.Fatalf("openLogFileIn: %v", err)
	}
	defer f.Close()

	w := teeWriter(brokenWriter{}, f)
	for _, line := range []string{"line one\n", "line two\n", "line three\n"} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("Write with broken console must still report success (file write is what matters): %v", err)
		}
	}
	f.Sync()

	data, err := os.ReadFile(filepath.Join(dir, logFileName))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := string(data)
	for _, want := range []string{"line one", "line two", "line three"} {
		if !strings.Contains(got, want) {
			t.Errorf("log file missing %q with a broken console writer -- got: %q", want, got)
		}
	}
}

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
