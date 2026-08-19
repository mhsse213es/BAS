//go:build linux || darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func buildCmd(ctx context.Context, step ScenarioStep) *exec.Cmd {
	switch strings.ToLower(step.Executor) {
	case "sh":
		return exec.CommandContext(ctx, "sh", "-c", step.Command)
	default:
		return exec.CommandContext(ctx, "bash", "-c", step.Command)
	}
}

// runCleanup executes the step's cleanup command and returns a verdict:
// "reverted" (exit 0), "partial" (non-zero exit), or "leaked" (start/timeout failure).
func runCleanup(step ScenarioStep) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", step.Cleanup)
	if step.PayloadDir != "" {
		cmd.Env = append(os.Environ(), "BAS_PAYLOAD_DIR="+step.PayloadDir)
	}
	err := cmd.Run()
	if err == nil {
		return "reverted"
	}
	if ctx.Err() != nil {
		return "leaked"
	}
	return "partial"
}

func collectRecentEvents(_ context.Context, _ time.Time) []string {
	return nil
}

// hostIsDomainController is always false on Linux/macOS — the DC interlock is a
// Windows Active Directory concept.
func hostIsDomainController() bool { return false }

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
