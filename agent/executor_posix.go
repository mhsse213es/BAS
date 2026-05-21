//go:build linux || darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
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
