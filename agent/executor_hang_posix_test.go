//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"audspect/agent/sched"
)

// forkingStep is a command whose shell forks rather than exec's, leaving a
// grandchild that inherits the step's stdout pipe. This is the shape that used
// to hang the agent permanently.
const forkingStep = "sleep 300 & echo started; sleep 300"

// A step whose shell forks a long-lived background child used to hang the
// agent forever. The direct child (bash) was killed on the execute deadline,
// but the orphaned grandchild inherited the step's stdout pipe and held it
// open; since cmd.Stdout is a bytes.Buffer, os/exec copies through an OS pipe
// and cmd.Wait blocks until every write end closes. Wait therefore never
// returned, so execStep never returned, so the step stayed RUNNING for the
// life of the agent.
//
// Before the Setpgid/terminateStepJob and WaitDelay fixes this blocks forever.
func TestExecStep_ForkedChildHoldingPipe_DoesNotHangForever(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}

	step := ScenarioStep{
		TaskID:   "hang-repro",
		Executor: "bash",
		Command:  forkingStep,
		Timeout:  &sched.TimeoutProfile{ExecuteSec: 1, GraceSec: 1},
	}

	// Generous next to ExecuteSec(1) + GraceSec(1) + waitDelaySlackSec(5), and
	// far below the "forever" the bug produced.
	const budget = 30 * time.Second

	type outcome struct {
		exitCode int
		stderr   string
	}
	done := make(chan outcome, 1)
	go func() {
		r := execStep(context.Background(), step, nil)
		done <- outcome{r.ExitCode, r.Stderr}
	}()

	select {
	case got := <-done:
		// Killed by our own deadline, so it must be reported as such, never as
		// a clean pass -- a timed-out step scored as success is exactly the
		// kind of flattering result that must never reach a client report.
		if got.exitCode == 0 {
			t.Errorf("ExitCode = 0 for a step killed by its execute deadline; want non-zero")
		}
		if strings.TrimSpace(got.stderr) == "" {
			t.Error("Stderr is empty; a deadline kill must explain itself")
		}
	case <-time.After(budget):
		t.Fatalf("execStep did not return within %s — cmd.Wait is blocked on pipes held by a surviving child", budget)
	}
}

// The operator-cancel path must also break a step whose shell forked. Cancel
// only cancels the context, so before the fix it wedged on the same blocked
// Wait -- which is why pressing Stop repeatedly did nothing at all.
func TestExecStep_CancelReturnsDespiteForkedChild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}

	step := ScenarioStep{
		TaskID:   "cancel-repro",
		Executor: "bash",
		Command:  forkingStep,
		// Long execute deadline: cancellation, not the deadline, must be what
		// ends this step.
		Timeout: &sched.TimeoutProfile{ExecuteSec: 600, GraceSec: 1},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- execStep(ctx, step, nil).ExitCode }()

	time.Sleep(500 * time.Millisecond) // let the shell fork its child
	cancel()

	select {
	case exitCode := <-done:
		if exitCode == 0 {
			t.Errorf("ExitCode = 0 for a cancelled step; want non-zero")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("execStep did not return after cancel — Stop cannot terminate a forked step")
	}
}

// terminateStepJob must reap the whole process group, not just its leader.
// This is the half that makes the kill orderly, rather than leaning on
// WaitDelay's abandon-the-pipes backstop.
func TestTerminateStepJob_KillsWholeProcessGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-dependent test in -short mode")
	}

	cmd := buildCmd(context.Background(), ScenarioStep{
		Executor: "bash",
		Command:  forkingStep,
	})
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid

	// buildCmd must have made the shell its own group leader — without that,
	// kill(-pid) would signal the test runner's own process group.
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("getpgid: %v", err)
	}
	if pgid != pid {
		t.Fatalf("pgid = %d, want %d — buildCmd must set Setpgid so the step leads its own group", pgid, pid)
	}

	terminateStepJob(0, pid)

	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err := <-waited:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("Wait err = %v, want an ExitError from the group SIGKILL", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("process group survived terminateStepJob")
	}
}
