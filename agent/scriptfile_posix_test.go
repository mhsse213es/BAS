//go:build linux || darwin

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func longShScript(n int, tail string) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString("# padding padding padding padding padding padding padding padding\n")
	}
	b.WriteString(tail)
	return b.String()
}

// A shell step larger than the 128 KB single-argument limit must still run,
// keep its exit code, stdout and stderr, and leave no script behind.
func TestLongShellStepRunsFromTempFile(t *testing.T) {
	for _, exe := range []string{"sh", "bash"} {
		t.Run(exe, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			s := ScenarioStep{
				TaskID: "long-sh", Executor: exe, TimeoutSec: 60,
				Command: longShScript(200000, "echo long-marker\necho err-marker >&2\nexit 7\n"),
			}
			r := execStep(context.Background(), s, nil)
			if r.ExitCode != 7 {
				t.Fatalf("exit code = %d, want 7 (stdout=%q stderr=%q)", r.ExitCode, r.Stdout, r.Stderr)
			}
			if !strings.Contains(r.Stdout, "long-marker") || !strings.Contains(r.Stderr, "err-marker") {
				t.Errorf("output lost: stdout=%q stderr=%q", r.Stdout, r.Stderr)
			}
			if left, _ := os.ReadDir(tmp); len(left) != 0 {
				t.Errorf("temp script not cleaned up: %d file(s)", len(left))
			}
		})
	}
}

func TestLongShellStepTimeoutLeavesNoTempFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	s := ScenarioStep{
		TaskID: "long-sh-timeout", Executor: "sh", TimeoutSec: 3,
		Command: longShScript(20000, "sleep 60\n"),
	}
	start := time.Now()
	r := execStep(context.Background(), s, nil)
	if !r.TimedOut {
		t.Fatalf("expected a timeout, got exit=%d stderr=%q", r.ExitCode, r.Stderr)
	}
	if time.Since(start) > 40*time.Second {
		t.Errorf("timeout took too long: %v", time.Since(start))
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temp script not cleaned up after timeout: %d file(s)", len(left))
	}
}

func TestShortShellStepIsNotMovedToAFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	s := ScenarioStep{TaskID: "short-sh", Executor: "sh", Command: "echo hi"}
	cmd := buildCmd(context.Background(), s)
	before := strings.Join(cmd.Args, "\x00")
	cleanup, err := stepScriptFile(cmd, s)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if strings.Join(cmd.Args, "\x00") != before {
		t.Errorf("short step arguments changed: %q", cmd.Args)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("short step wrote a file")
	}
}
