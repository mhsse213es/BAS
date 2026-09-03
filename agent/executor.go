package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"audspect/agent/protocol"
)

const maxOutputBytes = 8192

// declinePromptInput answers any interactive console prompt a scenario step
// might raise (e.g. reg.exe's `Overwrite (Yes/No)?`) with a safe "No" plus a
// newline, so the child proceeds or aborts instead of blocking on stdin until
// the step timeout. Without a real stdin the child reads the NUL device, gets
// EOF, and a Yes/No loop re-prompts in a tight loop — flooding output and
// burning the full 120s (seen in T1003.002 SAM dumping). "No" is the
// conservative answer: it declines destructive actions. Bounded (fits the OS
// pipe buffer, so it never deadlocks a step that ignores stdin) and ends at EOF
// so a pathological re-prompt loop still terminates.
func declinePromptInput() io.Reader {
	return strings.NewReader(strings.Repeat("n\r\n", 256))
}

func StagePayloads(payloads []protocol.Payload, dir string) error {
	for _, p := range payloads {
		data, err := base64.StdEncoding.DecodeString(p.Content)
		if err != nil {
			return fmt.Errorf("payload %q: base64 decode: %w", p.Name, err)
		}
		dest := filepath.Join(dir, p.Name)
		if err := os.WriteFile(dest, data, 0600); err != nil {
			return fmt.Errorf("payload %q: write: %w", p.Name, err)
		}
		// Remove the Zone.Identifier NTFS alternate data stream that Windows
		// automatically adds to files written by non-elevated processes.
		// Without this, executing a payload triggers the "Open File — Security
		// Warning" dialog ("Do you want to run this file?") which blocks the step
		// indefinitely waiting for a human to click Run.
		// This call is a no-op on Linux/macOS (path does not exist → ignored).
		os.Remove(dest + ":Zone.Identifier")
	}
	return nil
}

// CheckPayloadQuarantine waits briefly then checks whether any staged payload
// was removed by AV/EDR. Returns the first quarantined filename, or "".
func CheckPayloadQuarantine(payloads []protocol.Payload, dir string) string {
	time.Sleep(200 * time.Millisecond)
	for _, p := range payloads {
		if _, err := os.Stat(filepath.Join(dir, p.Name)); os.IsNotExist(err) {
			return p.Name
		}
	}
	return ""
}

// defaultGraceSec is the post-kill grace window when a step's profile doesn't set
// one: enough for a killed command's tree to wind down before forced termination.
const defaultGraceSec = 3

// waitDelaySlackSec is how long past the grace window cmd.WaitDelay allows
// before abandoning the stdout/stderr pipes. It only ever elapses when
// terminateStepJob's process-group kill failed to free them, so it is a
// backstop, not a routine cost.
const waitDelaySlackSec = 5

// executeSeconds resolves the step's execute-timeout (layer 2). Precedence:
// curated TimeoutProfile.ExecuteSec → legacy TimeoutSec → 120s blanket default.
func executeSeconds(step ScenarioStep) int {
	if step.Timeout != nil && step.Timeout.ExecuteSec > 0 {
		return step.Timeout.ExecuteSec
	}
	if step.TimeoutSec > 0 {
		return step.TimeoutSec
	}
	return 120
}

// graceSeconds resolves the post-kill grace window (layer 3).
func graceSeconds(step ScenarioStep) int {
	if step.Timeout != nil && step.Timeout.GraceSec > 0 {
		return step.Timeout.GraceSec
	}
	return defaultGraceSec
}

func execStep(parentCtx context.Context, step ScenarioStep, pool *HostPool) protocol.ExecResult {
	timeout := executeSeconds(step)
	grace := graceSeconds(step)

	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(timeout)*time.Second)
	defer cancel()

	before := time.Now()

	var preCleanupSnap *SystemSnapshot
	if step.Cleanup != "" {
		preCleanupSnap = captureSnapshotLite(step.TaskID)
	}

	// Fast path: read-only PowerShell discovery steps run on a warm pooled host,
	// skipping per-step process cold start. Each runs in a fresh runspace, so it is
	// isolated from other steps. A pool miss (ok=false) falls through to the robust
	// per-process path below — safe because only idempotent steps are pooled.
	if pool != nil && pooledCandidate(step) {
		if r, ok := pool.Run(ctx, step); ok {
			r.Events = collectRecentEvents(parentCtx, before)
			if step.Cleanup != "" {
				r.CleanupVerdict = runCleanup(step)
				r.CleanupResidual, r.CleanupVerdict = reconcileCleanupVerdict(
					preCleanupSnap, captureSnapshotLite(step.TaskID), r.CleanupVerdict)
			}
			// Pooled steps are observation-risk discovery running in the agent's
			// own context. Record what was requested vs what ran.
			r.RequestedPriv = step.RequiresPriv
			if step.RequiresPriv != "" {
				r.ExecutedAs = "admin"
			}
			return r
		}
	}

	cmd := buildCmd(ctx, step)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Never let an interactive prompt block the step on stdin (see helper).
	cmd.Stdin = declinePromptInput()

	// Hard bound on cmd.Wait itself -- the last line of defence, and the only
	// one that holds on every platform.
	//
	// Because Stdout/Stderr above are bytes.Buffers rather than *os.File,
	// os/exec spawns goroutines copying from OS pipes into them, and Wait
	// blocks until the process exits AND every write end of those pipes is
	// closed. A descendant that inherited the pipe keeps it open after the
	// direct child is killed, so Wait could block forever even though the
	// deadline fired on schedule -- leaving the step permanently RUNNING, with
	// the exit-code and timeout-marker code below unreachable. Cancel could not
	// clear it either: cancellation only cancels parentCtx, which converges on
	// this same blocked call, so repeated operator "Stop" presses were no-ops.
	// WaitDelay makes Wait give up on those pipes and return ErrWaitDelay,
	// keeping the run moving. Sized past the grace window so the orderly
	// terminateStepJob path below gets its chance first.
	cmd.WaitDelay = time.Duration(grace)*time.Second + waitDelaySlackSec*time.Second

	// Resolve execution context (user / admin / system). On Windows this may
	// switch to the logged-in user's token via WTS; on POSIX it is a no-op.
	// Must be called BEFORE setting cmd.Env below so user-context env is
	// established first and step overrides can then be layered on top.
	//
	// releaseExecCtx must stay open until after cmd.Start() has consumed it —
	// on Windows it holds the WTS token CreateProcessAsUserW needs at launch,
	// so deferring it here (rather than closing inside applyExecutionContext)
	// is required, not just tidy.
	executedAs, releaseExecCtx := applyExecutionContext(cmd, step)
	defer releaseExecCtx()

	// If applyExecutionContext did not already set cmd.Env (i.e. agent context),
	// apply step-level env overrides now.
	if cmd.Env == nil && (step.PayloadDir != "" || len(step.Env) > 0) {
		env := os.Environ()
		if step.PayloadDir != "" {
			env = append(env, "BAS_PAYLOAD_DIR="+step.PayloadDir)
		}
		for k, v := range step.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	// Use Start + Wait (instead of Run) so we can assign the process to a Job
	// Object between spawn and wait.  exec.CommandContext's own context-kill
	// goroutine is still active after Start — the Job Object adds a second kill
	// layer that reaches the ENTIRE process tree, including grandchildren and any
	// dialog-holding GUI processes that the parent spawned.
	if err := cmd.Start(); err != nil {
		stderrMsg := err.Error()
		// A scenario cancel that lands before this step even starts (e.g. the
		// scheduler had already queued it when the cancel arrived) must carry
		// the same unambiguous marker as a mid-flight kill below — otherwise
		// Go's raw "context canceled" text reaches the server as an opaque
		// exit -1, which classifyExecution defaults to a FAIL/finding.
		if parentCtx.Err() != nil {
			stderrMsg = "step interrupted by scenario cancellation"
		}
		return protocol.ExecResult{
			TaskID:        step.TaskID,
			ExitCode:      -1,
			Stderr:        stderrMsg,
			DurationMs:    time.Since(before).Milliseconds(),
			ExecutedAt:    time.Now(),
			RequestedPriv: step.RequiresPriv,
			ExecutedAs:    executedAs,
		}
	}

	// Register the child PID with the dialog dismisser so it can identify
	// dialog boxes that belong to this step (including grandchildren).
	childPID := uint32(cmd.Process.Pid)
	stepPID := cmd.Process.Pid
	trackExecPID(childPID)
	defer untrackExecPID(childPID)

	// Assign the child to a Job Object.  On timeout the goroutine below calls
	// TerminateJobObject which kills every process in the tree atomically.
	// On POSIX this is a no-op — process-group signal propagation is sufficient.
	job, jobErr := newStepJob(cmd.Process.Pid)
	if jobErr != nil {
		log.Printf("[exec] job assign: %v — timeout will only kill direct child", jobErr)
	}
	// Layer 3 (grace): on execute-timeout or scenario-cancel, CommandContext kills
	// the direct child; we then allow a grace window for the tree to wind down and
	// only hard-kill the whole process tree if it is still alive after grace.
	waitDone := make(chan struct{})
	go func() {
		select {
		case <-waitDone:
			return // step finished on its own — nothing to kill
		case <-ctx.Done():
		}
		if grace > 0 {
			t := time.NewTimer(time.Duration(grace) * time.Second)
			defer t.Stop()
			select {
			case <-waitDone:
				return // exited within grace
			case <-t.C:
			}
		}
		terminateStepJob(job, stepPID) // kills entire tree: parent + all spawned children, plus a PID sweep
	}()

	err := cmd.Wait()
	close(waitDone)
	dur := time.Since(before).Milliseconds()

	// An execute-timeout (our deadline) is an explicit "ran, did not return"
	// verdict — distinct from a scenario abort (parent cancel) or a clean finish.
	timedOut := ctx.Err() == context.DeadlineExceeded && parentCtx.Err() == nil

	// Close the Job handle — KILL_ON_JOB_CLOSE terminates any processes that
	// somehow survived both the context kill and TerminateJobObject.
	closeStepJob(job)

	exitCode := 0
	blocked := false
	blockedReason := ""

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			// Only flag as security block when neither the step timeout nor a
			// scenario-cancel triggered the kill — those are our own kills.
			if ctx.Err() == nil && parentCtx.Err() == nil {
				blocked, blockedReason = detectSecurityBlock(exitErr, dur)
			}
		} else {
			exitCode = -1
		}
	}

	if timedOut {
		exitCode = -1
		if strings.TrimSpace(stderr.String()) == "" {
			fmt.Fprintf(&stderr, "step exceeded execute timeout of %ds", timeout)
		}
	}

	// WaitDelay elapsed: the step's process tree was killed, but something in it
	// still held the output pipes, so os/exec abandoned them and returned early.
	// Say so rather than shipping an unexplained exit -1 — stdout/stderr here are
	// whatever was captured before the pipes were dropped, so the step's output
	// may be truncated, and a reader deserves to know that. Note this leaves a
	// process alive on the host: worth surfacing, not silently swallowing.
	if errors.Is(err, exec.ErrWaitDelay) {
		exitCode = -1
		log.Printf("[exec] %s: output pipes abandoned after WaitDelay — a descendant survived the process-group kill", step.TaskID)
		fmt.Fprintf(&stderr, "\n[agent] step output abandoned after %ds: a child process outlived the kill and kept the output pipe open; captured output may be truncated",
			grace+waitDelaySlackSec)
	}

	// The step was still in-flight when the scenario itself was cancelled
	// (stuck-technique force-cancel, manual stop, agent shutdown/disconnect
	// watchdog) — tag it unambiguously rather than leaving a bare exit -1, so
	// the server (classifyExecutionError, internal/scenario/outcome.go) can
	// exclude this kill artifact from findings instead of scoring it as a
	// real "control did not prevent it" result.
	if !timedOut && parentCtx.Err() != nil {
		exitCode = -1
		if strings.TrimSpace(stderr.String()) == "" {
			stderr.WriteString("step interrupted by scenario cancellation")
		}
	}

	result := protocol.ExecResult{
		TaskID:        step.TaskID,
		PID:           stepPID,
		StartedAt:     before,
		ExitCode:      exitCode,
		Stdout:        trimOutput(stdout.Bytes()),
		Stderr:        trimOutput(stderr.Bytes()),
		DurationMs:    dur,
		ExecutedAt:    time.Now(),
		Blocked:       blocked,
		BlockedReason: blockedReason,
		TimedOut:      timedOut,
		RequestedPriv: step.RequiresPriv,
		ExecutedAs:    executedAs,
	}

	result.Events = collectRecentEvents(parentCtx, before)

	if step.Cleanup != "" {
		result.CleanupVerdict = runCleanup(step)
		result.CleanupResidual, result.CleanupVerdict = reconcileCleanupVerdict(
			preCleanupSnap, captureSnapshotLite(step.TaskID), result.CleanupVerdict)
	}

	return result
}

// reconcileCleanupVerdict lets snapshot-diff evidence override the raw
// exit-code verdict from runCleanup when they disagree: an exit-0 "reverted"
// verdict downgrades to "partial" if evidence shows residue left behind; a
// timed-out "leaked" verdict upgrades to "reverted" if evidence shows nothing
// left behind. "partial" is left unchanged either way — the spec calls out
// only these two specific overrides. A nil pre or post (snapshot capture
// unavailable) skips reconciliation entirely and returns the raw verdict
// unchanged with a nil residual — this never blocks or fails the step.
func reconcileCleanupVerdict(pre, post *SystemSnapshot, verdict string) ([]string, string) {
	if pre == nil || post == nil {
		return nil, verdict
	}
	residual := diffSnapshots(pre, post)
	switch {
	case verdict == "reverted" && len(residual) > 0:
		return residual, "partial"
	case verdict == "leaked" && len(residual) == 0:
		return residual, "reverted"
	default:
		return residual, verdict
	}
}

func trimOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > maxOutputBytes {
		return s[:maxOutputBytes] + "…"
	}
	return s
}
