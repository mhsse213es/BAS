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

// Payload is a file the server wants staged on the endpoint before the step runs.
// Content is base64-encoded. The agent writes it to PayloadDir/<Name> before execution.
type Payload struct {
	Name    string `json:"name"`    // filename, e.g. "invoke-mimikatz.ps1"
	Content string `json:"content"` // base64-encoded file content
}

// ScenarioStep is sent by the server — one concrete command for the agent to run.
// The server resolves all framework-specific logic (ART, Caldera, etc.) before sending.
// The agent has no knowledge of frameworks; it only sees executor + command.
type ScenarioStep struct {
	TaskID      string    `json:"taskId"`      // stable ID for result correlation
	TechniqueID string    `json:"techniqueId"` // informational only (logging + telemetry)
	Name        string    `json:"name"`        // informational only (logging)
	Executor    string    `json:"executor"`    // see execStep for supported values
	Command     string    `json:"command"`     // ready-to-run — no framework knowledge needed
	TimeoutSec  int       `json:"timeoutSec"`
	Payloads    []Payload `json:"payloads,omitempty"` // files to stage before running
	Cleanup     string    `json:"cleanup,omitempty"`  // command to run after step (pass or fail)
	PayloadDir  string    `json:"-"`                  // set at runtime by runScenario
}

// ExecResult is the raw output the agent returns per step.
// No interpretation — the server's interpreter.go does all pass/fail logic.
type ExecResult struct {
	TaskID     string    `json:"taskId"`
	ExitCode   int       `json:"exitCode"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	DurationMs int64     `json:"durationMs"`
	ExecutedAt time.Time `json:"executedAt"`
	// Events are Windows Event IDs observed during step execution (Security + Sysmon).
	// Empty if event collection is unavailable or the step runs too fast to generate events.
	Events []string `json:"events,omitempty"`
}

const maxOutputBytes = 8192

// StagePayloads decodes and writes each Payload to dir. Returns the dir path.
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

// execStep runs a single ScenarioStep and returns the raw result.
func execStep(step ScenarioStep) ExecResult {
	timeout := step.TimeoutSec
	if timeout <= 0 {
		timeout = 120
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	before := time.Now()
	cmd := buildCmd(ctx, step)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Expose payload directory to the command via environment variable.
	// Server-generated commands can reference %BAS_PAYLOAD_DIR% (cmd) or
	// $env:BAS_PAYLOAD_DIR (PowerShell) without the agent knowing what's in it.
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

	// Collect Windows events generated during this step.
	result.Events = collectRecentEvents(before)

	// Run cleanup command if present — fire and forget, does not affect result.
	if step.Cleanup != "" {
		go runCleanup(step)
	}

	return result
}

// buildCmd constructs the exec.Cmd for the given executor type.
//
// Supported executors:
//   - powershell / ps1  : PowerShell 5/7 (default)
//   - cmd               : Windows Command Prompt
//   - wmi               : Win32_Process.Create — tests WMI-based execution detection (T1047)
//   - mshta             : mshta.exe — LOLBin HTA/VBScript execution path (T1218.005)
//   - rundll32          : rundll32.exe — LOLBin DLL execution (T1218.011)
//   - cscript / wscript : Windows Script Host execution (T1059.005/007)
//   - regsvr32          : regsvr32.exe — Squiblydoo technique (T1218.010)
//   - schtasks          : schtasks.exe — scheduled task execution (T1053.005)
func buildCmd(ctx context.Context, step ScenarioStep) *exec.Cmd {
	switch strings.ToLower(step.Executor) {
	case "cmd":
		return exec.CommandContext(ctx, "cmd", "/c", step.Command)

	case "wmi":
		// WMI process creation: tests if EDR detects Win32_Process.Create (T1047).
		// Wraps inner command to write output to a temp file, then reads it back so
		// we still capture stdout even though WMI spawns a detached process.
		tmpOut := filepath.Join(os.Getenv("TEMP"), fmt.Sprintf("bas-wmi-%d.txt", time.Now().UnixNano()))
		// Single-quoted strings inside the outer double-quoted Create() arg need escaping.
		innerCmd := strings.ReplaceAll(step.Command, "'", "''")
		wmiScript := fmt.Sprintf(`
$tmp = '%s'
$inner = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& { %s } 2>&1 | Out-File -FilePath ''%s'' -Encoding utf8"'
([wmiclass]'Win32_Process').Create($inner) | Out-Null
$deadline = (Get-Date).AddSeconds(28)
do { Start-Sleep -Milliseconds 500 } while (!(Test-Path $tmp) -and (Get-Date) -lt $deadline)
if (Test-Path $tmp) { Get-Content $tmp; Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
else { Write-Output "WMI_TIMEOUT: inner process did not write output within timeout" }
`, tmpOut, innerCmd, tmpOut)
		return exec.CommandContext(ctx, "powershell",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-Command", wmiScript)

	case "mshta":
		// MSHTA LOLBin: command is an inline VBScript expression or path to .hta file.
		// Example: "vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run(\"\"cmd /c whoami > %TEMP%\out.txt\"\"):close\")"
		return exec.CommandContext(ctx, "mshta.exe", step.Command)

	case "rundll32":
		// RundLL32 LOLBin: command is "path\to.dll,EntryPoint [args]"
		// Example: "shell32.dll,Control_RunDLL desk.cpl,,0"
		parts := strings.Fields(step.Command)
		if len(parts) == 0 {
			parts = []string{step.Command}
		}
		return exec.CommandContext(ctx, "rundll32.exe", parts...)

	case "cscript":
		// Windows Script Host (cscript): command is path to .vbs/.js file with optional args
		parts := append([]string{"//nologo"}, strings.Fields(step.Command)...)
		return exec.CommandContext(ctx, "cscript.exe", parts...)

	case "wscript":
		// Windows Script Host (wscript — GUI): same as cscript but no console window
		parts := append([]string{"//nologo"}, strings.Fields(step.Command)...)
		return exec.CommandContext(ctx, "wscript.exe", parts...)

	case "regsvr32":
		// Squiblydoo (T1218.010): regsvr32 /s /u /i:<url> scrobj.dll
		// command is the full argument string, e.g. "/s /u /i:http://... scrobj.dll"
		return exec.CommandContext(ctx, "regsvr32.exe", strings.Fields(step.Command)...)

	case "schtasks":
		// Scheduled task creation/execution (T1053.005)
		// command is the full schtasks argument string
		return exec.CommandContext(ctx, "schtasks.exe", strings.Fields(step.Command)...)

	default: // "powershell", "ps1", or anything unrecognised
		return exec.CommandContext(ctx, "powershell",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-Command", step.Command)
	}
}

// collectRecentEvents collects Windows Security and Sysmon Event IDs generated
// since `since`. Returns a deduplicated sorted list of "EventID:LogName" strings.
// Returns nil on any error (non-fatal — telemetry is best-effort).
func collectRecentEvents(since time.Time) []string {
	// Allow a short settling time so events flushed slightly after cmd.Run() returns are included.
	time.Sleep(300 * time.Millisecond)

	sinceStr := since.UTC().Format("2006-01-02T15:04:05")
	ps := fmt.Sprintf(`
$since = [datetime]'%s'
$logs  = @('Security', 'Microsoft-Windows-Sysmon/Operational')
$out   = @()
foreach ($log in $logs) {
    try {
        $evts = Get-WinEvent -MaxEvents 200 -FilterHashtable @{LogName=$log; StartTime=$since} -ErrorAction SilentlyContinue
        foreach ($e in $evts) { $out += "$($e.Id):$log" }
    } catch {}
}
($out | Sort-Object -Unique) -join ","
`, sinceStr)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", ps).Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}

// runCleanup executes the cleanup command for a step (fire-and-forget).
// Errors are logged but do not affect the step result.
func runCleanup(step ScenarioStep) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", step.Cleanup)
	if step.PayloadDir != "" {
		cmd.Env = append(os.Environ(), "BAS_PAYLOAD_DIR="+step.PayloadDir)
	}
	if err := cmd.Run(); err != nil {
		// Cleanup failures are non-fatal — log only.
		_ = err
	}
}

func trimOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > maxOutputBytes {
		return s[:maxOutputBytes] + "…"
	}
	return s
}
