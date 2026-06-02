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

func runCleanup(step ScenarioStep) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", step.Cleanup)
	if step.PayloadDir != "" {
		cmd.Env = append(os.Environ(), "BAS_PAYLOAD_DIR="+step.PayloadDir)
	}
	_ = cmd.Run()
}

func collectRecentEvents(_ context.Context, _ time.Time) []string {
	return nil
}

// hostIsDomainController is always false on Linux/macOS — the DC interlock is a
// Windows Active Directory concept.
func hostIsDomainController() bool { return false }

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
