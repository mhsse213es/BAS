//go:build windows

package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"audspect/agent/protocol"
	"audspect/agent/sched"
)

// A console command that prompts on stdin (here cmd's `set /p`, the same pattern
// reg.exe uses for "Overwrite (Yes/No)?") must be answered by declinePromptInput
// and complete promptly — not hang reading the NUL device until killed.
func TestDeclinePromptInputAnswersConsolePrompt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// set /p blocks until it reads a line from stdin; echo proves what it got.
	// /v:on enables delayed expansion so !ANS! reflects the value read at runtime
	// (plain %ANS% would expand at parse time, before set /p runs).
	cmd := exec.CommandContext(ctx, "cmd", "/v:on", "/c", "set /p ANS=Overwrite? & echo ANS=[!ANS!]")
	cmd.Stdin = declinePromptInput()

	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("prompting command hung on stdin — declinePromptInput did not answer it")
	}
	if err != nil {
		t.Fatalf("command error: %v (out=%q)", err, out)
	}
	if !strings.Contains(string(out), "ANS=[n]") {
		t.Errorf("prompt was not answered with 'n'; output=%q", string(out))
	}
}

// TestExecStepExecuteTimeout verifies layer 2: a command that runs past its
// execute timeout is killed and returns an explicit TimedOut verdict (exit -1)
// within the timeout window — not after the command's own 30s sleep.
func TestExecStepExecuteTimeout(t *testing.T) {
	step := ScenarioStep{
		TaskID:   "to",
		Executor: "powershell",
		Command:  "Start-Sleep -Seconds 30",
		Timeout:  &sched.TimeoutProfile{ExecuteSec: 1, GraceSec: 1},
	}
	start := time.Now()
	r := execStep(context.Background(), step, nil)
	elapsed := time.Since(start)

	if !r.TimedOut {
		t.Errorf("expected TimedOut=true, got %+v", r)
	}
	if r.ExitCode != -1 {
		t.Errorf("expected exit -1 on timeout, got %d", r.ExitCode)
	}
	if r.Blocked {
		t.Error("a timeout must not be misreported as a security block")
	}
	if elapsed > 15*time.Second {
		t.Errorf("execute timeout not honored: took %v for a 1s timeout", elapsed)
	}
}

// TestExecStepCancelNotTimeout verifies a scenario abort (parent cancel) is NOT
// reported as an execute timeout.
func TestExecStepCancelNotTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // abort before the step runs

	r := execStep(ctx, ScenarioStep{
		TaskID:   "c",
		Executor: "powershell",
		Command:  "Start-Sleep -Seconds 30",
		Timeout:  &sched.TimeoutProfile{ExecuteSec: 30},
	}, nil)

	if r.TimedOut {
		t.Error("scenario cancel was misreported as an execute timeout")
	}
	if r.ExitCode != -1 {
		t.Errorf("expected exit -1 on scenario cancel, got %d", r.ExitCode)
	}
	// The server must be able to tell a kill artifact apart from a real
	// technique result — otherwise a stuck-technique force-cancel or a
	// manual stop can masquerade as "control did not prevent it" and
	// generate a false finding. See internal/scenario/outcome.go's
	// matching classifyExecutionError case on the orchestrator side.
	if !strings.Contains(r.Stderr, "step interrupted by scenario cancellation") {
		t.Errorf("expected the cancellation marker in Stderr so the server excludes this step from findings, got %q", r.Stderr)
	}
}

// TestRunCleanup_CapturesFailureDetail proves a failing cleanup command's own
// stderr/exit code is captured and reported, not silently discarded. Before
// this, runCleanup returned a bare "partial"/"leaked" verdict with no way to
// tell why -- found via a real production report showing a leaked temp file
// with zero diagnostic trail anywhere in scenario_runs.results.
func TestRunCleanup_CapturesFailureDetail(t *testing.T) {
	const marker = "definitely-does-not-exist-xyz123"
	step := ScenarioStep{
		Cleanup: "Remove-Item -Path 'C:\\" + marker + "' -ErrorAction Stop",
	}
	verdict, detail := runCleanup(step)
	if verdict != "partial" {
		t.Fatalf("verdict = %q, want %q", verdict, "partial")
	}
	if detail == "" {
		t.Fatal("detail = \"\", want the cleanup command's own stderr/exit code captured")
	}
	if !strings.Contains(detail, marker) {
		t.Errorf("detail = %q, want it to contain the failing command's own error text (marker %q)", detail, marker)
	}
}

// TestRunCleanup_SuccessReportsNoDetail confirms a successful cleanup still
// returns an empty detail string -- detail is only meaningful evidence for a
// failure, never noise on the common path.
func TestRunCleanup_SuccessReportsNoDetail(t *testing.T) {
	step := ScenarioStep{Cleanup: "exit 0"}
	verdict, detail := runCleanup(step)
	if verdict != "reverted" {
		t.Fatalf("verdict = %q, want %q", verdict, "reverted")
	}
	if detail != "" {
		t.Errorf("detail = %q, want empty on success", detail)
	}
}

// canReachDomainController's fail-safe contract (increment 2.1, 2026-10-09):
// LDAP timeout, DNS failure, an unreachable DC, and a malformed RootDSE
// response are all indistinguishable at the probe-execution layer -- they
// either make the real PowerShell script's own try/catch exit 1, or make the
// process itself run past its deadline. runPowerShellProbeWithTimeout is the
// extracted mechanism both canReachDomainController's real LDAP probe and
// these tests exercise, so the fail-safe behavior is proven with real
// processes (this file's existing convention, e.g.
// TestExecStepExecuteTimeout) instead of needing a live AD lab.

// TestCanReachDomainController_ProbeSucceedsOnCleanExit: a DC-reachable probe
// (real script: no exception from the LDAP RootDSE bind) exits 0.
func TestCanReachDomainController_ProbeSucceedsOnCleanExit(t *testing.T) {
	if !runPowerShellProbeWithTimeout(5*time.Second, "exit 0") {
		t.Error("a clean exit 0 must be treated as reachable")
	}
}

// TestCanReachDomainController_ProbeFailsSafeOnError stands in for DNS
// failure / unreachable DC / malformed RootDSE response: the real script's
// try/catch maps every one of those into exit 1. Must be treated as
// unreachable, never silently as success.
func TestCanReachDomainController_ProbeFailsSafeOnError(t *testing.T) {
	if runPowerShellProbeWithTimeout(5*time.Second, "exit 1") {
		t.Error("a non-zero exit (DNS failure / unreachable DC / malformed response) must be treated as unreachable")
	}
}

// TestCanReachDomainController_ProbeFailsSafeOnTimeout stands in for an LDAP
// call that hangs (e.g. a DC that accepts the connection but never answers):
// the context deadline must kill it promptly and report unreachable, never
// block indefinitely or report success.
func TestCanReachDomainController_ProbeFailsSafeOnTimeout(t *testing.T) {
	start := time.Now()
	ok := runPowerShellProbeWithTimeout(300*time.Millisecond, "Start-Sleep -Seconds 10")
	elapsed := time.Since(start)
	if ok {
		t.Error("a probe that times out must be treated as unreachable")
	}
	if elapsed > 5*time.Second {
		t.Errorf("timeout not honored: took %v for a 300ms timeout", elapsed)
	}
}

// TestCanReachDomainController_CompletesWithinItsTimeout pins the real
// function's wiring to its own timeout constant without asserting the
// boolean result (which depends on whether THIS build host is domain-joined)
// -- only the time bound is deterministic across environments.
func TestCanReachDomainController_CompletesWithinItsTimeout(t *testing.T) {
	// The function's own worst-case bound is dcProbeTimeout+hardProbeSlack
	// (the hard outer deadline in runPowerShellProbeWithTimeout); this test
	// adds its own margin on top for scheduling jitter, rather than reusing
	// the exact same bound the code enforces.
	bound := dcProbeTimeout + hardProbeSlack + 3*time.Second
	start := time.Now()
	_ = canReachDomainController()
	if elapsed := time.Since(start); elapsed > bound {
		t.Errorf("canReachDomainController took %v, want <= %v (dcProbeTimeout %v + hardProbeSlack %v + test margin)",
			elapsed, bound, dcProbeTimeout, hardProbeSlack)
	}
}

// The next two tests close increment 2.2's property-3 gap (cleanup on
// cancellation): runCleanup has direct unit tests in isolation, but nothing
// proved cleanup still runs, through the real execStep path, when the main
// command is killed by an operator cancel or an execute timeout rather than
// exiting on its own. Both derive the main command's kill from the SAME
// mechanism agent.go's real cancellation paths use (parentCtx cancellation /
// the execute-timeout deadline); runCleanup's own context is deliberately
// independent of parentCtx (executor_windows.go), so cleanup gets its own
// full window regardless of why the main command died.

// TestExecStepCleanupRunsAfterOperatorCancel proves an operator cancel
// (parentCtx cancelled while the main command is still running) does not
// skip the step's cleanup command.
func TestExecStepCleanupRunsAfterOperatorCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	step := ScenarioStep{
		TaskID:   "cleanup-cancel",
		Executor: "powershell",
		Command:  "Start-Sleep -Seconds 30",
		Cleanup:  "exit 0",
		Timeout:  &sched.TimeoutProfile{ExecuteSec: 600, GraceSec: 2},
	}
	out := make(chan protocol.ExecResult, 1)
	go func() { out <- execStep(ctx, step, nil) }()

	// Found while writing this test (2026-10-09): when step.Cleanup is set,
	// execStep captures a pre-cleanup snapshot (captureSnapshotLite) BEFORE
	// starting the main command, and that capture alone took >1s on this
	// host. A short delay here would fire cancel() before cmd.Start() even
	// runs, hitting the "never started" early-return path instead of
	// actually killing a running process -- a different, already-correct
	// case, not the one this test means to exercise. 2s gives Start() room
	// to be reached first, so cancel() lands on a genuinely running step.
	time.Sleep(2 * time.Second)
	cancel() // operator cancel, not a timeout

	select {
	case r := <-out:
		if r.TimedOut {
			t.Fatalf("TimedOut = true, want false -- this was an operator cancel, not an execute-timeout")
		}
		if r.CleanupVerdict != "reverted" {
			t.Fatalf("CleanupVerdict = %q, want %q -- cleanup must still run and succeed after a cancel", r.CleanupVerdict, "reverted")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("execStep did not return within 15s of cancel -- cleanup may be blocking on the cancelled parentCtx instead of its own independent context")
	}
}

// TestExecStepCleanupRunsAfterExecuteTimeout proves an execute-timeout kill
// (the step's own ExecuteSec deadline, not an external cancel) also does not
// skip the step's cleanup command.
func TestExecStepCleanupRunsAfterExecuteTimeout(t *testing.T) {
	step := ScenarioStep{
		TaskID:   "cleanup-timeout",
		Executor: "powershell",
		Command:  "Start-Sleep -Seconds 30",
		Cleanup:  "exit 0",
		// ExecuteSec must leave room for step.Cleanup's pre-cleanup snapshot
		// capture (captureSnapshotLite), which runs BEFORE cmd.Start() and
		// took >1s on this host -- too tight a deadline fires before the
		// main command ever starts, hitting the "never started" early-return
		// path instead of actually timing out a running command.
		Timeout: &sched.TimeoutProfile{ExecuteSec: 5, GraceSec: 2},
	}

	out := make(chan protocol.ExecResult, 1)
	go func() { out <- execStep(context.Background(), step, nil) }()

	select {
	case r := <-out:
		if !r.TimedOut {
			t.Fatalf("TimedOut = false, want true")
		}
		if r.CleanupVerdict != "reverted" {
			t.Fatalf("CleanupVerdict = %q, want %q -- cleanup must still run and succeed after an execute-timeout kill", r.CleanupVerdict, "reverted")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("execStep did not return within 15s of its 1s timeout -- cleanup may be blocking indefinitely")
	}
}
