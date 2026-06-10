//go:build windows

package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas-agent/sched"
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
}
