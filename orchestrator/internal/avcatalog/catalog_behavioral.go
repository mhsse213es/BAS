package avcatalog

import "github.com/audspect/bas/internal/avval"

// behavioralVectors seeds av.txt §2.C (Behavioral detection and exploit
// prevention): process-injection-pattern and suspicious-child-process-chain
// simulations, separated from EDR-specific investigation/response
// capabilities (av.txt §2.C closing note).
//
// AV-BEHAV-001 harness contract (av.txt's own 6-step directive: define the
// contract before building, never leave a vector blocked or silently
// claimed as implemented when it cannot execute):
//
//   - Invocation: dispatched exactly like every other seed vector, through
//     the standard "powershell" executor -- no new agent capability, no
//     separate binary artifact, no new transfer/signing/execution
//     infrastructure. This reuses the exact pattern already reviewed and
//     shipped in scenarios/endpoint-mastery/em-03-memory-attacks.yaml's own
//     "Cross-process memory WRITE (injection precursor)" step: Add-Type
//     compiles a small P/Invoke shim in memory, which genuinely IS building
//     a small, deterministic native-code-backed test executable -- just
//     JIT'd on the agent rather than shipped pre-built. A standalone
//     prebuilt .exe would need new agent-side binary-delivery, integrity,
//     and execution infrastructure that does not exist anywhere in this
//     codebase today; that remains a separate, larger project, not
//     justified for this one vector.
//   - Prerequisites: Windows, a .NET/PowerShell C# compiler available for
//     Add-Type (checked at runtime; SKIP, never a crash, if unavailable),
//     and the ability to spawn a disposable notepad.exe as the injection
//     target. No admin privilege is required -- VirtualAllocEx/
//     WriteProcessMemory into a same-user-owned process needs no
//     elevation, unlike LSASS access.
//   - Behavior exercised: OpenProcess(VM_OPERATION|VM_WRITE|VM_READ) +
//     VirtualAllocEx + WriteProcessMemory of a benign ASCII marker into the
//     disposable target. NO CreateRemoteThread, NO code execution -- the
//     injection PRECURSOR primitive only, identical safety boundary to
//     em-03's own reviewed step. A no-op binary that merely starts and
//     exits would NOT satisfy this: the real Win32 calls, and their real
//     success/failure, are the thing being measured.
//   - Observations: Prevention is observed directly (EvidenceObserved) from
//     the WriteProcessMemory call's own return value -- never inferred.
//     Detection is a SEPARATE, best-effort check of this endpoint's own
//     local Windows Defender operational event log (EIDs 1116/1117) for
//     any entry timestamped at or after this run started; this is real
//     local telemetry, not a tenant-gated remote API, but it is reported
//     UNAVAILABLE rather than fabricated when that log cannot be queried.
//     A "FAIL" (injection succeeded) is deliberately NOT equated with a
//     confirmed gap by this vector alone -- internal/avval's own
//     derivePrevention requires an agreeing Detection-axis observation
//     (Detected, or verified NotObservedInWindow) before a PreventionAllowed
//     result resolves to FindingConfirmedGap; absent one, it stays
//     Inconclusive. See internal/avefficacy's dispatch bridge, which builds
//     exactly this two-source evidence shape from a real dispatch result.
//   - Result/exit mapping: stdout "PASS: " (blocked/denied) or "FAIL: "
//     (succeeded unblocked) or "SKIP: " (a prerequisite above was missing),
//     plus a machine-parseable "detection=DETECTED|NOT_OBSERVED|UNAVAILABLE"
//     token -- the same convention the dispatch bridge parses.
//   - Timeout: the adapter's uniform 30s default (internal/avscenario);
//     the script itself only waits 300ms for the disposable target to
//     settle, well inside that budget.
//   - Cleanup: the disposable notepad.exe is terminated unconditionally
//     (even on the denied-access path) before the script returns, and
//     CleanupCommand sweeps any stray hidden notepad.exe as a second,
//     idempotent safety net -- mirrors em-03's own cleanup exactly.
func behavioralVectors() ([]Vector, error) {
	var out []Vector

	v1, err := NewVector(
		"AV-BEHAV-001", 1, FamilyBehavioralExploit,
		"Self-injection into a disposable test process",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has a behavioral/NGAV engine capable of memory/injection-indicator inspection; a disposable test process is available as the injection target",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "powershell",
			Command: `$ErrorActionPreference = 'SilentlyContinue'
$marker = '[BAS-SIM-AVBEHAV001] T1055 injection-precursor marker - no code, no thread'
$sig = @'
using System;
using System.Runtime.InteropServices;
public static class BasAvBehav001 {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, uint size, uint type, uint prot);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, uint size, out UIntPtr written);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool VirtualFreeEx(IntPtr h, IntPtr addr, uint size, uint type);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
}
'@
try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch { Write-Output "SKIP: could not compile P/Invoke probe (no .NET compiler available)."; return }
$startedAt = Get-Date
$t = Start-Process 'notepad.exe' -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 300
if (-not $t) { Write-Output "SKIP: could not start disposable test process."; return }
$h = [BasAvBehav001]::OpenProcess(0x002A, $false, $t.Id)
$wrote = $false
if ($h -ne [IntPtr]::Zero) {
  $buf = [System.Text.Encoding]::ASCII.GetBytes($marker)
  $rem = [BasAvBehav001]::VirtualAllocEx($h, [IntPtr]::Zero, [uint32]$buf.Length, 0x3000, 0x04)
  if ($rem -ne [IntPtr]::Zero) {
    $written = [UIntPtr]::Zero
    $wrote = [BasAvBehav001]::WriteProcessMemory($h, $rem, $buf, [uint32]$buf.Length, [ref]$written)
    [void][BasAvBehav001]::VirtualFreeEx($h, $rem, 0, 0x8000)
  }
  [void][BasAvBehav001]::CloseHandle($h)
}
Stop-Process -Id $t.Id -Force -ErrorAction SilentlyContinue
$detection = 'UNAVAILABLE'
try {
  $events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop | Where-Object { ($_.Id -eq 1116 -or $_.Id -eq 1117) -and $_.TimeCreated -ge $startedAt }
  if ($events) { $detection = 'DETECTED' } else { $detection = 'NOT_OBSERVED' }
} catch { $detection = 'UNAVAILABLE' }
if ($wrote) { Write-Output "FAIL: VirtualAllocEx + WriteProcessMemory into a disposable process succeeded unblocked -- code-injection primitives are available. detection=$detection [BAS-SIM-AVBEHAV001]" }
else { Write-Output "PASS: remote memory allocation/write was denied or prevented. detection=$detection [BAS-SIM-AVBEHAV001]" }`,
			Description:    "spawn a disposable notepad.exe and attempt OpenProcess+VirtualAllocEx+WriteProcessMemory of a benign marker into it (the T1055 injection precursor, no remote thread, no code execution), then check this endpoint's own local Windows Defender operational log for a correlating detection event",
			CleanupCommand: `Get-Process notepad -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq '' } | Stop-Process -Force -ErrorAction SilentlyContinue`,
		},
		nil,
		"process-injection APIs have no close legitimate business counterpart suitable for a false-positive comparison in this vector; legitimate-tooling false-positive resilience for injection-adjacent techniques (debuggers, EDR agents themselves) is covered separately under §2.H",
		"terminate the disposable test process and confirm no injected artifact persists",
		"the real Defender-log detection check above is local-telemetry-only and best-effort: it reports UNAVAILABLE rather than a fabricated result when the operational log cannot be queried, and a benign marker payload is unlikely to trigger a signature-based detection event even when a product's behavioral layer does block the underlying API calls -- a PASS (blocked) stands on its own, but a FAIL (succeeded) with no corresponding Detection evidence resolves to Inconclusive, not a confirmed gap, under internal/avval's own evidence rules; validating this harness against a real AV/NGAV product on a dedicated lab endpoint remains separate, deferred work (see docs/av-mastery-qa-log.md)",
		StandardsMapping{ATTACKTechniques: []string{"T1055"}},
		"manually authored from av.txt §2.C",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewVector(
		"AV-BEHAV-002", 1, FamilyBehavioralExploit,
		"Suspicious child-process chain from a simulated document reader",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has a behavioral/NGAV engine capable of parent-child process-chain inspection",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile','-Command','Set-Content -Path "$env:TEMP\avtest-docreader-marker.txt" -Value marker' -Wait -WindowStyle Hidden`,
			ArtifactPath:   `%TEMP%\avtest-docreader-marker.txt`,
			Description:    "spawn a script interpreter (powershell.exe) as a child process, simulating a document-reader application whose child process's only action is a benign marker write",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-docreader-marker.txt" -Force -ErrorAction SilentlyContinue`,
		},
		&ExecutionTemplate{
			Executor:    "powershell",
			Command:     `Start-Process -FilePath "cmd.exe" -ArgumentList '/c','echo printing' -Wait -WindowStyle Hidden`,
			Description: "spawn the same simulated document-reader application's normal, expected non-interpreter helper child process, with no persistent side effect",
		},
		"",
		"delete the marker file written by either leg",
		"",
		StandardsMapping{ATTACKTechniques: []string{"T1566.001", "T1059.001"}},
		"manually authored from av.txt §2.C",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
