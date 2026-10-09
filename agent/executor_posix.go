//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func buildCmd(ctx context.Context, step ScenarioStep) *exec.Cmd {
	var cmd *exec.Cmd
	switch strings.ToLower(step.Executor) {
	case "sh":
		cmd = exec.CommandContext(ctx, "sh", "-c", step.Command)
	default:
		cmd = exec.CommandContext(ctx, "bash", "-c", step.Command)
	}
	// Put the shell in its own process group so terminateStepJob can signal the
	// WHOLE tree with kill(-pgid). Without this the child shares the agent's
	// group, so a group kill is impossible and exec.CommandContext's own
	// cancellation -- which is cmd.Process.Kill(), a single-PID SIGKILL -- reaps
	// only the direct child. A shell that forks (pipelines, &&, subshells,
	// backgrounded work) then leaves descendants running that still hold the
	// inherited stdout/stderr pipe open, and cmd.Wait blocks on those pipes
	// forever even though the step's deadline fired on time.
	//
	// applyExecutionContext only fills SysProcAttr when it is nil and otherwise
	// just sets Credential, so setting it here is safe alongside user-context
	// switching.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

// runCleanup executes the step's cleanup command and returns a verdict --
// "reverted" (exit 0), "partial" (non-zero exit), or "leaked" (start/timeout
// failure) -- plus a detail string. detail is empty on success; on failure it
// captures the cleanup command's own stderr and exit code, which used to be
// silently discarded, leaving a "partial"/"leaked" verdict with no way to
// tell why the cleanup script didn't remove what it was supposed to.
func runCleanup(step ScenarioStep) (verdict, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", step.Cleanup)
	if step.PayloadDir != "" {
		cmd.Env = append(os.Environ(), "BAS_PAYLOAD_DIR="+step.PayloadDir)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return "reverted", ""
	}
	if ctx.Err() != nil {
		return "leaked", fmt.Sprintf("cleanup timed out after 30s: %s", trimOutput(stderr.Bytes()))
	}
	exitCode := -1
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}
	return "partial", fmt.Sprintf("exit %d: %s", exitCode, trimOutput(stderr.Bytes()))
}

func collectRecentEvents(_ context.Context, _ time.Time) []string {
	return nil
}

// hostIsDomainController is always false on Linux/macOS — the DC interlock is a
// Windows Active Directory concept.
func hostIsDomainController() bool { return false }

// canReachDomainController is always false on Linux/macOS — AD domain-controller
// reachability is not implemented on this platform. A scenario that sets
// live_policy.require_dc_reachable is Windows-specific in practice (enforced by
// the server-side supported_os check before dispatch), so this path is not
// expected to be exercised for a genuinely cross-platform scenario.
func canReachDomainController() bool { return false }

// applyExecutionContext resolves the privilege context for a step and, for
// "user" steps, switches the child process to the interactive user's identity
// via SysProcAttr.Credential — the POSIX equivalent of CreateProcessAsUser.
//
// Requires the agent to be running as root (CAP_SETUID/CAP_SETGID).
//
// The returned cleanup func has nothing to release on POSIX (Credential is a
// plain value, not a handle) — it exists only to keep the signature identical
// to the Windows build, which does hold a closable token.
func applyExecutionContext(cmd *exec.Cmd, step ScenarioStep) (string, func()) {
	noop := func() {}
	switch step.RequiresPriv {
	case "":
		return "", noop
	case "admin", "system":
		return step.RequiresPriv, noop
	case "user":
		ctx, ok := activeUserCtx()
		if !ok {
			// No interactive session — fall back to agent context, record honestly.
			return "user→admin", noop
		}
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid:         ctx.uid,
			Gid:         ctx.gid,
			Groups:      ctx.groups,
			NoSetGroups: len(ctx.groups) == 0,
		}
		cmd.Env = buildPosixUserEnv(ctx, step)
		return "user", noop
	default:
		return "", noop
	}
}

// detectSecurityBlock returns true when an EDR/AV killed the child process.
// SIGKILL from our own context (timeout/cancel) is excluded by the caller.
func detectSecurityBlock(exitErr *exec.ExitError, durMs int64) (bool, string) {
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return false, ""
	}
	if !status.Signaled() {
		return false, ""
	}
	switch status.Signal() {
	case syscall.SIGKILL:
		return true, "process killed by SIGKILL — terminated by EDR or security control"
	case syscall.SIGTERM:
		// SIGTERM within 500 ms of start → external security tool, not a graceful shutdown
		if durMs < 500 {
			return true, "process terminated by SIGTERM within 500ms — likely blocked by security control"
		}
	}
	return false, ""
}
