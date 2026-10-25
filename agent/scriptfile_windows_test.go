//go:build windows

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// longPSScript pads a script with comment lines to at least n bytes, then
// appends the real work, so the script is far past the Windows command-line
// limit but still trivially valid PowerShell.
func longPSScript(n int, tail string) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString("# padding padding padding padding padding padding padding padding\n")
	}
	b.WriteString(tail)
	return b.String()
}

// A PowerShell step too long for a command line must still run: it goes
// through a temp file, keeps its exit code, stdout and stderr, and leaves no
// file behind.
func TestLongPowerShellStepRunsFromTempFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)
	s := ScenarioStep{
		TaskID: "long-ps", Executor: "powershell", TimeoutSec: 60,
		Command: longPSScript(40000, "Write-Output 'long-marker'\n[Console]::Error.WriteLine('err-marker')\nexit 7\n"),
	}
	r := execStep(context.Background(), s, nil)
	if r.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7 (stdout=%q stderr=%q)", r.ExitCode, r.Stdout, r.Stderr)
	}
	if !strings.Contains(r.Stdout, "long-marker") {
		t.Errorf("stdout missing marker: %q", r.Stdout)
	}
	if !strings.Contains(r.Stderr, "err-marker") {
		t.Errorf("stderr missing marker: %q", r.Stderr)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temp script not cleaned up: %d file(s) left", len(left))
	}
}

// A step killed by its timeout must not leave its script behind either.
func TestLongPowerShellStepTimeoutLeavesNoTempFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)
	s := ScenarioStep{
		TaskID: "long-ps-timeout", Executor: "powershell", TimeoutSec: 3,
		Command: longPSScript(40000, "Start-Sleep -Seconds 60\n"),
	}
	start := time.Now()
	r := execStep(context.Background(), s, nil)
	if !r.TimedOut {
		t.Fatalf("expected a timeout, got exit=%d stdout=%q stderr=%q", r.ExitCode, r.Stdout, r.Stderr)
	}
	if time.Since(start) > 40*time.Second {
		t.Errorf("timeout took too long: %v", time.Since(start))
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temp script not cleaned up after timeout: %d file(s) left", len(left))
	}
}

// A short step keeps today's launch path: no temp file, same arguments.
func TestShortPowerShellStepIsNotMovedToAFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)
	s := ScenarioStep{TaskID: "short-ps", Executor: "powershell", Command: "Write-Output hi"}
	cmd := buildCmd(context.Background(), s)
	before := strings.Join(cmd.Args, "\x00")
	cleanup, err := stepScriptFile(cmd, s)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if after := strings.Join(cmd.Args, "\x00"); after != before {
		t.Errorf("short step arguments changed:\n before %q\n after  %q", before, after)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("short step wrote a file: %d", len(left))
	}
}
