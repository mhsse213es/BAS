//go:build windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Windows process creation flags.
const (
	createNoWindow      = 0x08000000 // no console window, no GUI window on initial create
	createNewProcessGrp = 0x00000200 // own Ctrl+C group — breaks console inheritance
)

// silentCmd applies creation flags to every scenario step command so that:
//   - No console or GUI window is created (CREATE_NO_WINDOW)
//   - HideWindow hint is passed via STARTUPINFO (SW_HIDE) — suppresses main window
//   - The child is in its own Ctrl+C group (CREATE_NEW_PROCESS_GROUP) to avoid
//     inadvertently killing the agent when we cancel a step
//
// This is the primary defence against interactive dialogs blocking scenario steps.
func silentCmd(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow | createNewProcessGrp,
	}
	return cmd
}

func buildCmd(ctx context.Context, step ScenarioStep) *exec.Cmd {
	switch strings.ToLower(step.Executor) {
	case "cmd":
		return silentCmd(exec.CommandContext(ctx, "cmd", "/c", step.Command))

	case "wmi":
		// WMI creates a new session via Win32_Process.Create, which bypasses any
		// SysProcAttr we set on the outer shell.  Force the inner process hidden by
		// passing -WindowStyle Hidden and -NonInteractive explicitly.
		tmpOut := filepath.Join(os.Getenv("TEMP"), fmt.Sprintf("bas-wmi-%d.txt", time.Now().UnixNano()))
		innerCmd := strings.ReplaceAll(step.Command, "'", "''")
		wmiScript := fmt.Sprintf(`
$tmp = '%s'
$inner = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& { %s } 2>&1 | Out-File -FilePath ''%s'' -Encoding utf8"'
([wmiclass]'Win32_Process').Create($inner) | Out-Null
$deadline = (Get-Date).AddSeconds(28)
do { Start-Sleep -Milliseconds 500 } while (!(Test-Path $tmp) -and (Get-Date) -lt $deadline)
if (Test-Path $tmp) { Get-Content $tmp; Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
else { Write-Output "WMI_TIMEOUT: inner process did not write output within timeout" }
`, tmpOut, innerCmd, tmpOut)
		return silentCmd(exec.CommandContext(ctx, "powershell",
			"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass",
			"-Command", wmiScript))

	case "mshta":
		// mshta.exe is a GUI host — CREATE_NO_WINDOW alone does not prevent it from
		// creating new windows after startup.  Wrap it in Start-Process so PowerShell
		// applies SW_HIDE to the mshta window and waits for completion.
		safeArg := strings.ReplaceAll(step.Command, "'", "''")
		wrapped := fmt.Sprintf(
			`Start-Process -FilePath mshta.exe -ArgumentList '%s' -WindowStyle Hidden -Wait`,
			safeArg)
		return silentCmd(exec.CommandContext(ctx, "powershell",
			"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass",
			"-Command", wrapped))

	case "wscript":
		// wscript.exe is a GUI host — same treatment as mshta.
		safeArg := strings.ReplaceAll(step.Command, "'", "''")
		wrapped := fmt.Sprintf(
			`Start-Process -FilePath wscript.exe -ArgumentList '//nologo %s' -WindowStyle Hidden -Wait`,
			safeArg)
		return silentCmd(exec.CommandContext(ctx, "powershell",
			"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass",
			"-Command", wrapped))

	case "rundll32":
		parts := strings.Fields(step.Command)
		if len(parts) == 0 {
			parts = []string{step.Command}
		}
		return silentCmd(exec.CommandContext(ctx, "rundll32.exe", parts...))

	case "cscript":
		// cscript is a console host — CREATE_NO_WINDOW is sufficient.
		parts := append([]string{"//nologo", "//B"}, strings.Fields(step.Command)...)
		return silentCmd(exec.CommandContext(ctx, "cscript.exe", parts...))

	case "regsvr32":
		// /s = silent (no success/failure dialog)
		args := append([]string{"/s"}, strings.Fields(step.Command)...)
		return silentCmd(exec.CommandContext(ctx, "regsvr32.exe", args...))

	case "schtasks":
		return silentCmd(exec.CommandContext(ctx, "schtasks.exe", strings.Fields(step.Command)...))

	default: // powershell / psh
		return silentCmd(exec.CommandContext(ctx, "powershell",
			"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass",
			"-Command", step.Command))
	}
}

// applyExecutionContext resolves the privilege context for a step, optionally
// switches the cmd to run under the logged-in user's token (for "user" steps),
// and returns the label that should be recorded in ExecResult.ExecutedAs plus
// a cleanup func that closes the token.
//
// The token must stay open until after cmd.Start() has used it: exec.Cmd.Start
// passes SysProcAttr.Token to CreateProcessAsUserW as-is, it does NOT duplicate
// it first. Closing the token before Start() runs (as this function used to do
// via its own defer) invalidates the handle out from under CreateProcessAsUserW,
// which fails every such launch with "the handle is invalid". The caller must
// defer the returned cleanup itself, after Start() has been called.
func applyExecutionContext(cmd *exec.Cmd, step ScenarioStep) (string, func()) {
	tok, label := agentContextFor(step)
	if tok == 0 {
		return label, func() {} // running in agent's own context — no token switch needed
	}

	env, _ := buildUserEnv(tok, step)
	cmd.Env = env

	// Set Token on SysProcAttr — exec.Cmd.Start calls CreateProcessAsUserW when
	// this is non-zero, spawning the child in the user's security context.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Token = syscall.Token(tok)
	return label, func() { tok.Close() }
}

// hostIsDomainController reports whether this Windows host is a domain controller.
// The DC role is recorded in ProductOptions\ProductType = "LanmanNT" (DC) vs
// "WinNT" (workstation) / "ServerNT" (member server).
func hostIsDomainController() bool {
	out, err := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions`, "/v", "ProductType").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "LanmanNT")
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
	cmd := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", step.Cleanup)
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

// detectSecurityBlock returns true when an EDR/AV terminated the child process.
// Recognised Windows patterns:
//
//	0xC0000005 STATUS_ACCESS_VIOLATION  — memory execution blocked
//	0xC0000022 STATUS_ACCESS_DENIED     — file/process access denied by AV
//	exit -1 in <500 ms               — TerminateProcess called almost immediately
func detectSecurityBlock(exitErr *exec.ExitError, durMs int64) (bool, string) {
	code := uint32(exitErr.ExitCode())
	switch code {
	case 0xC0000005:
		return true, "process blocked: STATUS_ACCESS_VIOLATION — execution denied by security control"
	case 0xC0000022:
		return true, "process blocked: STATUS_ACCESS_DENIED — execution denied by security control"
	case 0xC000013A: // STATUS_CONTROL_C_EXIT — intentional, not a block
		return false, ""
	}
	// ExitCode -1 means TerminateProcess was used; very short run = external kill
	if exitErr.ExitCode() == -1 && durMs < 500 {
		return true, "process terminated externally within 500ms — likely blocked by EDR or AV"
	}
	return false, ""
}

func collectRecentEvents(parentCtx context.Context, since time.Time) []string {
	select {
	case <-parentCtx.Done():
		return nil
	default:
	}

	time.Sleep(300 * time.Millisecond)

	sinceStr := since.UTC().Format("2006-01-02T15:04:05")
	// Collect telemetry the server can correlate into a detection verdict. The
	// Defender Operational log carries real threat detections (event IDs 1116/1117
	// etc.); Security and Sysmon carry process/activity visibility. We emit raw
	// "id:log" tokens — interpretation (detected vs merely logged) is the server's
	// job, keeping the agent a dumb collector.
	ps := fmt.Sprintf(`
$since = [datetime]'%s'
$logs  = @('Security', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Windows Defender/Operational')
$out   = @()
foreach ($log in $logs) {
    try {
        $evts = Get-WinEvent -MaxEvents 200 -FilterHashtable @{LogName=$log; StartTime=$since} -ErrorAction SilentlyContinue
        foreach ($e in $evts) { $out += "$($e.Id):$log" }
    } catch {}
}
($out | Sort-Object -Unique) -join ","
`, sinceStr)

	ctx, cancel := context.WithTimeout(parentCtx, 8*time.Second)
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
