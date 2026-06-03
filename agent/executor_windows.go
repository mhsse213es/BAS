//go:build windows

package main

import (
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

func runCleanup(step ScenarioStep) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", step.Cleanup)
	if step.PayloadDir != "" {
		cmd.Env = append(os.Environ(), "BAS_PAYLOAD_DIR="+step.PayloadDir)
	}
	_ = cmd.Run()
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
