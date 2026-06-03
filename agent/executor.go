package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
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

	// Use Start + Wait (instead of Run) so we can assign the process to a Job
	// Object between spawn and wait.  exec.CommandContext's own context-kill
	// goroutine is still active after Start — the Job Object adds a second kill
	// layer that reaches the ENTIRE process tree, including grandchildren and any
	// dialog-holding GUI processes that the parent spawned.
	if err := cmd.Start(); err != nil {
		return ExecResult{
			TaskID:     step.TaskID,
			ExitCode:   -1,
			Stderr:     err.Error(),
			DurationMs: time.Since(before).Milliseconds(),
			ExecutedAt: time.Now(),
		}
	}

	// Register the child PID with the dialog dismisser so it can identify
	// dialog boxes that belong to this step (including grandchildren).
	childPID := uint32(cmd.Process.Pid)
	trackExecPID(childPID)
	defer untrackExecPID(childPID)

	// Assign the child to a Job Object.  On timeout the goroutine below calls
	// TerminateJobObject which kills every process in the tree atomically.
	// On POSIX this is a no-op — process-group signal propagation is sufficient.
	job, jobErr := newStepJob(cmd.Process.Pid)
	if jobErr != nil {
		log.Printf("[exec] job assign: %v — timeout will only kill direct child", jobErr)
	}
	go func() {
		<-ctx.Done()
		terminateStepJob(job) // kills entire tree: parent + all spawned children
	}()

	err := cmd.Wait()
	dur := time.Since(before).Milliseconds()

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
