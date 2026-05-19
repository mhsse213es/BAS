package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Payload is a file staged on the endpoint before a step runs.
type Payload struct {
	Name    string `json:"name"`
	Content string `json:"content"` // base64-encoded
}

// ScenarioStep is the server-resolved command the agent executes.
// All framework logic (ART, Caldera, etc.) is handled by the orchestrator before sending.
type ScenarioStep struct {
	TaskID      string    `json:"taskId"`
	TechniqueID string    `json:"techniqueId"`
	Name        string    `json:"name"`
	Executor    string    `json:"executor"`
	Command     string    `json:"command"`
	TimeoutSec  int       `json:"timeoutSec"`
	Payloads    []Payload `json:"payloads,omitempty"`
	Cleanup     string    `json:"cleanup,omitempty"`
	PayloadDir  string    `json:"-"`
}

// ExecResult is the raw output per step — no interpretation, orchestrator does that.
type ExecResult struct {
	TaskID     string    `json:"taskId"`
	ExitCode   int       `json:"exitCode"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	DurationMs int64     `json:"durationMs"`
	ExecutedAt time.Time `json:"executedAt"`
}

const maxOutputBytes = 8192

func StagePayloads(payloads []Payload, dir string) error {
	for _, p := range payloads {
		data, err := base64.StdEncoding.DecodeString(p.Content)
		if err != nil {
			return fmt.Errorf("payload %q: base64 decode: %w", p.Name, err)
		}
		dest := filepath.Join(dir, p.Name)
		if err := os.WriteFile(dest, data, 0600); err != nil {
			return fmt.Errorf("payload %q: write: %w", p.Name, err)
		}
	}
	return nil
}

func execStep(parentCtx context.Context, step ScenarioStep) ExecResult {
	timeout := step.TimeoutSec
	if timeout <= 0 {
		timeout = 120
	}

	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(timeout)*time.Second)
	defer cancel()

	before := time.Now()
	cmd := buildCmd(ctx, step)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if step.PayloadDir != "" {
		cmd.Env = append(os.Environ(), "BAS_PAYLOAD_DIR="+step.PayloadDir)
	}

	err := cmd.Run()
	dur := time.Since(before).Milliseconds()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	result := ExecResult{
		TaskID:     step.TaskID,
		ExitCode:   exitCode,
		Stdout:     trimOutput(stdout.Bytes()),
		Stderr:     trimOutput(stderr.Bytes()),
		DurationMs: dur,
		ExecutedAt: time.Now(),
	}

	if step.Cleanup != "" {
		go runCleanup(step)
	}

	return result
}

// buildCmd supports bash (default) and sh executors.
func buildCmd(ctx context.Context, step ScenarioStep) *exec.Cmd {
	switch strings.ToLower(step.Executor) {
	case "sh":
		return exec.CommandContext(ctx, "sh", "-c", step.Command)
	default: // bash, local, or anything unrecognised
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

func trimOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > maxOutputBytes {
		return s[:maxOutputBytes] + "…"
	}
	return s
}
