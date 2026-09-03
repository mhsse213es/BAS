//go:build linux || darwin

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"audspect/agent/sched"
)

// floodStdout emits output forever. Combined with a short execute deadline this
// is the shape the old code could not survive: an unbounded bytes.Buffer grew
// until the step ended, so `grep -ri password /` (a real atomic in the full ART
// sweep) streamed the filesystem into the agent's heap.
const floodStdout = "yes bas-output-flood-payload"

// boundedOutput is the ceiling any captured stream may occupy: the retained
// bytes plus the truncation marker. Generous slack so the assertion is about
// the bound holding, not the marker's exact wording.
const boundedOutput = maxOutputBytes + 256

func runStep(t *testing.T, ctx context.Context, step ScenarioStep, budget time.Duration) protocol_result {
	t.Helper()
	done := make(chan protocol_result, 1)
	go func() {
		r := execStep(ctx, step, nil)
		done <- protocol_result{r.ExitCode, r.Stdout, r.Stderr, r.TimedOut}
	}()
	select {
	case got := <-done:
		return got
	case <-time.After(budget):
		t.Fatalf("execStep did not return within %s", budget)
		return protocol_result{}
	}
}

type protocol_result struct {
	exitCode int
	stdout   string
	stderr   string
	timedOut bool
}

// The headline case: a step producing far more than the cap must leave the
// agent's retained output bounded.
func TestExecStep_HugeOutputIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}
	got := runStep(t, context.Background(), ScenarioStep{
		TaskID:   "flood",
		Executor: "bash",
		Command:  floodStdout,
		Timeout:  &sched.TimeoutProfile{ExecuteSec: 1, GraceSec: 1},
	}, 30*time.Second)

	if len(got.stdout) > boundedOutput {
		t.Errorf("retained stdout = %d bytes, want <= %d — the cap is not bounding memory", len(got.stdout), boundedOutput)
	}
	if !strings.Contains(got.stdout, "output truncated") {
		t.Error("truncated output carries no marker; a reader cannot tell output was dropped")
	}
}

// THE NASTY CASE: huge output combined with a timeout, where process I/O and
// cancellation interact. The bound must hold, the step must still be reported
// as timed out, and -- the regression this guards -- the timeout explanation
// must survive. Agent diagnostics are appended outside the cap precisely so a
// noisy step cannot discard the one line saying why it failed.
func TestExecStep_HugeOutputPlusTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}
	got := runStep(t, context.Background(), ScenarioStep{
		TaskID:   "flood-timeout",
		Executor: "bash",
		// Floods BOTH streams, so neither can rely on the other being quiet.
		Command: floodStdout + " & yes bas-err-flood >&2",
		Timeout: &sched.TimeoutProfile{ExecuteSec: 1, GraceSec: 1},
	}, 30*time.Second)

	if len(got.stdout) > boundedOutput {
		t.Errorf("retained stdout = %d bytes, want <= %d", len(got.stdout), boundedOutput)
	}
	if !got.timedOut {
		t.Error("step killed by its execute deadline was not reported as timed out")
	}
	if got.exitCode == 0 {
		t.Error("ExitCode = 0 for a timed-out step; want non-zero")
	}
	// stderr was flooded past the cap, so this line can only be present if
	// agent notes live outside the capped region.
	if !strings.Contains(got.stderr, "exceeded execute timeout") &&
		!strings.Contains(got.stderr, "[agent]") {
		t.Errorf("no agent diagnostic survived a flooded stderr:\n%.500s", got.stderr)
	}
	if len(got.stderr) > boundedOutput+512 {
		t.Errorf("retained stderr = %d bytes, want bounded", len(got.stderr))
	}
}

// Operator cancel against a flooding step: same bound, same requirement that
// the step actually returns.
func TestExecStep_HugeOutputPlusCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	got := runStep(t, ctx, ScenarioStep{
		TaskID:   "flood-cancel",
		Executor: "bash",
		Command:  floodStdout,
		// Long deadline: cancellation must be what ends this, not the timeout.
		Timeout: &sched.TimeoutProfile{ExecuteSec: 600, GraceSec: 1},
	}, 30*time.Second)

	if len(got.stdout) > boundedOutput {
		t.Errorf("retained stdout = %d bytes, want <= %d", len(got.stdout), boundedOutput)
	}
	if got.exitCode == 0 {
		t.Error("ExitCode = 0 for a cancelled step; want non-zero")
	}
}

// Composition check: flooding output AND a forked child that outlives the kill
// holding the pipe. Bounding memory does NOT close pipes, so cmd.Wait can still
// block here -- WaitDelay remains what guarantees return. This asserts the two
// mechanisms work together rather than one masking the other.
func TestExecStep_HugeOutputWithForkedChildStillReturns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}
	got := runStep(t, context.Background(), ScenarioStep{
		TaskID:   "flood-fork",
		Executor: "bash",
		Command:  "sleep 300 & " + floodStdout,
		Timeout:  &sched.TimeoutProfile{ExecuteSec: 1, GraceSec: 1},
	}, 40*time.Second)

	if len(got.stdout) > boundedOutput {
		t.Errorf("retained stdout = %d bytes, want <= %d", len(got.stdout), boundedOutput)
	}
	if got.exitCode == 0 {
		t.Error("ExitCode = 0 for a step killed by its deadline; want non-zero")
	}
}

// Ordinary well-behaved output must pass through untouched -- the cap must not
// alter, mark, or truncate a normal step's result.
func TestExecStep_SmallOutputUnaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}
	got := runStep(t, context.Background(), ScenarioStep{
		TaskID:   "small",
		Executor: "bash",
		Command:  "echo hello-from-step",
		Timeout:  &sched.TimeoutProfile{ExecuteSec: 10, GraceSec: 1},
	}, 20*time.Second)

	if strings.TrimSpace(got.stdout) != "hello-from-step" {
		t.Errorf("stdout = %q, want %q unchanged", got.stdout, "hello-from-step")
	}
	if got.exitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", got.exitCode)
	}
}
