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

// CheckPayloadQuarantine waits briefly then checks whether any staged payload
// was removed by AV/EDR. Returns the first quarantined filename, or "".
func CheckPayloadQuarantine(payloads []Payload, dir string) string {
	time.Sleep(200 * time.Millisecond)
	for _, p := range payloads {
		if _, err := os.Stat(filepath.Join(dir, p.Name)); os.IsNotExist(err) {
			return p.Name
		}
	}
	return ""
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

	if step.PayloadDir != "" || len(step.Env) > 0 {
		env := os.Environ()
		if step.PayloadDir != "" {
			env = append(env, "BAS_PAYLOAD_DIR="+step.PayloadDir)
		}
		for k, v := range step.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	err := cmd.Run()
	dur := time.Since(before).Milliseconds()

	exitCode := 0
	blocked := false
	blockedReason := ""

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			// Only flag as security block when neither the step timeout nor a
			// scenario-cancel triggered the kill — those are our own SIGKILLs.
			if ctx.Err() == nil && parentCtx.Err() == nil {
				blocked, blockedReason = detectSecurityBlock(exitErr, dur)
			}
		} else {
			exitCode = -1
		}
	}

	result := ExecResult{
		TaskID:        step.TaskID,
		ExitCode:      exitCode,
		Stdout:        trimOutput(stdout.Bytes()),
		Stderr:        trimOutput(stderr.Bytes()),
		DurationMs:    dur,
		ExecutedAt:    time.Now(),
		Blocked:       blocked,
		BlockedReason: blockedReason,
	}

	result.Events = collectRecentEvents(parentCtx, before)

	if step.Cleanup != "" {
		go runCleanup(step)
	}

	return result
}

func trimOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > maxOutputBytes {
		return s[:maxOutputBytes] + "…"
	}
	return s
}
