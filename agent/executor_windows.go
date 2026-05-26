//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func buildCmd(ctx context.Context, step ScenarioStep) *exec.Cmd {
	switch strings.ToLower(step.Executor) {
	case "cmd":
		return exec.CommandContext(ctx, "cmd", "/c", step.Command)

	case "wmi":
		tmpOut := filepath.Join(os.Getenv("TEMP"), fmt.Sprintf("bas-wmi-%d.txt", time.Now().UnixNano()))
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
		return exec.CommandContext(ctx, "mshta.exe", step.Command)

	case "rundll32":
		parts := strings.Fields(step.Command)
		if len(parts) == 0 {
			parts = []string{step.Command}
		}
		return exec.CommandContext(ctx, "rundll32.exe", parts...)

	case "cscript":
		parts := append([]string{"//nologo"}, strings.Fields(step.Command)...)
		return exec.CommandContext(ctx, "cscript.exe", parts...)

	case "wscript":
		parts := append([]string{"//nologo"}, strings.Fields(step.Command)...)
		return exec.CommandContext(ctx, "wscript.exe", parts...)

	case "regsvr32":
		return exec.CommandContext(ctx, "regsvr32.exe", strings.Fields(step.Command)...)

	case "schtasks":
		return exec.CommandContext(ctx, "schtasks.exe", strings.Fields(step.Command)...)

	default:
		return exec.CommandContext(ctx, "powershell",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-Command", step.Command)
	}
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
//   0xC0000005 STATUS_ACCESS_VIOLATION  — memory execution blocked
//   0xC0000022 STATUS_ACCESS_DENIED     — file/process access denied by AV
//   exit -1 in <500 ms               — TerminateProcess called almost immediately
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
