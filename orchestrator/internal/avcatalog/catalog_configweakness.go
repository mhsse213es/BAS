package avcatalog

import "github.com/audspect/bas/internal/avval"

// configurationWeaknessVectors seeds av.txt §2.D (Configuration and
// security-control weaknesses), limited to the three scenario families
// (av.txt §3) that require an actual test execution to demonstrate the
// weakness: exclusion weakness, degraded (cloud-lookup-unavailable)
// protection, and security tampering. The rest of §2.D (stale signatures,
// policy drift, conflicting policies) remains a snapshot-vs-baseline
// comparison with no Vector shape (see this package's own doc comment).
func configurationWeaknessVectors() ([]Vector, error) {
	var out []Vector

	v1, err := NewVector(
		"AV-CONFIG-001", 1, FamilyConfigurationWeakness,
		"Known test artifact placed inside a configured scan exclusion",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilitySignatureAV},
		"a specific directory has been added to the AV's scan exclusions by the tester/customer as this test's precondition (e.g. C:\\AVTest\\ExclusionZone); this vector never configures the exclusion itself",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "powershell",
			Command: `New-Item -ItemType Directory -Path "C:\AVTest\ExclusionZone" -Force | Out-Null; ` +
				`Set-Content -Path "C:\AVTest\ExclusionZone\avtest-eicar-exclusion.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'`,
			ArtifactPath:   `C:\AVTest\ExclusionZone\avtest-eicar-exclusion.txt`,
			Description:    "write the EICAR test string inside the tester-configured exclusion path, to measure whether the exclusion creates a demonstrable protection gap beyond what was intentionally excluded",
			CleanupCommand: `Remove-Item -Path "C:\AVTest\ExclusionZone" -Recurse -Force -ErrorAction SilentlyContinue`,
		},
		&ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Set-Content -Path "$env:TEMP\avtest-eicar-no-exclusion.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'`,
			ArtifactPath:   `%TEMP%\avtest-eicar-no-exclusion.txt`,
			Description:    "write the identical EICAR test string to a path NOT covered by any exclusion, proving the comparison isolates the exclusion's own effect rather than a general scanning failure",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-eicar-no-exclusion.txt" -Force -ErrorAction SilentlyContinue`,
		},
		"",
		"delete the exclusion-zone directory and the unexcluded comparison file",
		"this vector measures the exclusion's effect; it does not itself judge whether the exclusion is business-justified -- that is a policy question outside this test's scope",
		StandardsMapping{ATTACKTechniques: []string{"T1562.001"}},
		"manually authored from av.txt §2.D / §3 'Exclusion weakness'",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewVector(
		"AV-CONFIG-002", 1, FamilyConfigurationWeakness,
		"Known test artifact with cloud-reputation lookup unavailable",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilitySignatureAV, CapabilityBehavioralNGAV},
		"the endpoint's cloud-reputation lookup has been disabled or blocked via the product's own management console, or a controlled network block configured by the tester, as this test's precondition -- this vector never alters network connectivity or product settings itself",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Set-Content -Path "$env:TEMP\avtest-eicar-degraded.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'`,
			ArtifactPath:   `%TEMP%\avtest-eicar-degraded.txt`,
			Description:    "write the EICAR test string while cloud-lookup connectivity is unavailable, to measure whether local, offline protection still operates as expected",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-eicar-degraded.txt" -Force -ErrorAction SilentlyContinue`,
		},
		nil,
		"degraded-mode testing has no distinct benign counterpart needed for this vector: the comparable legitimate-file case is already covered by AV-FILE-001's benign leg under normal (non-degraded) connectivity",
		"delete the dropped test file; restore cloud-reputation connectivity afterward if this test disabled it at the product/network level (outside this vector's own command)",
		"a product whose local engine legitimately depends on cloud lookups for this specific signature may show an expected, non-gap Inconclusive/Allowed result here -- this vector measures observed behavior, not a presumed correct answer",
		StandardsMapping{ATTACKTechniques: []string{"T1204.002"}},
		"manually authored from av.txt §2.D / §3 'Degraded protection'",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	// AV-CONFIG-003 harness contract: a vector can be implemented without
	// being generally dispatchable. This one is permanently excluded from
	// every ordinary, general-purpose dispatchable scenario bundle (see
	// LabRestrictedVectorIDs in eligibility.go, and the cross-package
	// regression test in internal/avscenario that asserts it never
	// appears in dispatchableSeedVectorIDs). Its definition is separated
	// from its execution eligibility by three independent layers, each
	// of which must pass before any mutating call is even attempted:
	//
	//  1. LabRestrictedVectorIDs -- a structural, catalog-level fact that
	//     no caller can silently bypass by adding this ID to a different
	//     dispatch list.
	//  2. BAS_CONFIRM_AV_RTP_DISABLE_ATTEMPT -- an explicit, human-set
	//     execution gate checked by the command itself (mirroring the
	//     existing BAS_CONFIRM_VSS_DELETE gate in internal/rwevidence's
	//     ransomware vertical). Absent the gate, the command SKIPs before
	//     touching any product setting at all.
	//  3. A real precondition check (Get-MpComputerStatus's
	//     IsTamperProtected AND RealTimeProtectionEnabled) run even after
	//     the gate is confirmed. If either is false, the command SKIPs
	//     rather than attempting Set-MpPreference -- deliberately never
	//     disabling protection merely to demonstrate that disabling
	//     protection creates a gap. This is the "harmless, denied
	//     configuration-change attempt" the test is designed around: it
	//     only ever proceeds when a denial is the expected, safe outcome.
	//
	// After a genuine attempt, the command unconditionally restores
	// Set-MpPreference -DisableRealtimeMonitoring $false regardless of
	// outcome, then re-reads status to report the real resulting state --
	// never inferring success from the absence of a thrown exception.
	// Every SKIP path reports "restricted"/"untested" explicitly in its
	// own stdout text; none of them is ever counted as a passing test by
	// internal/avefficacy's dispatch bridge (a "skipped" CheckResult
	// resolves Inconclusive there, never a fabricated success).
	v3, err := NewVector(
		"AV-CONFIG-003", 1, FamilyConfigurationWeakness,
		"Attempt to disable real-time protection via an unauthorized path",
		SeverityCritical,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has tamper protection AND real-time protection both already enabled (re-verified by the command itself immediately before any attempt, never merely assumed); the explicit BAS_CONFIRM_AV_RTP_DISABLE_ATTEMPT execution gate is set; this vector must only run on a dedicated, isolated lab endpoint under its own execution gate, never a build/production host or a routine campaign",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "powershell",
			Command: `$ErrorActionPreference = 'SilentlyContinue'
if (-not $env:BAS_CONFIRM_AV_RTP_DISABLE_ATTEMPT) {
  Write-Output "SKIP (restricted): BAS_CONFIRM_AV_RTP_DISABLE_ATTEMPT not set -- this vector requires an explicit execution gate and must never run outside a dedicated, isolated lab endpoint. [BAS-SIM-AVCONFIG003]"
  return
}
$status = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $status) {
  Write-Output "SKIP (untested): Get-MpComputerStatus unavailable -- cannot verify preconditions. [BAS-SIM-AVCONFIG003]"
  return
}
if (-not $status.IsTamperProtected -or -not $status.RealTimeProtectionEnabled) {
  Write-Output "SKIP (restricted): preconditions not met (IsTamperProtected=$($status.IsTamperProtected), RealTimeProtectionEnabled=$($status.RealTimeProtectionEnabled)) -- both must already be true before this test attempts a change, so a denial is the expected outcome rather than a real risk. Never disabling protection merely to demonstrate a gap. [BAS-SIM-AVCONFIG003]"
  return
}
$startedAt = Get-Date
try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop } catch {}
Start-Sleep -Milliseconds 300
$after = Get-MpComputerStatus -ErrorAction SilentlyContinue
$afterRTP = if ($after) { $after.RealTimeProtectionEnabled } else { $null }
try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}
$detection = 'UNAVAILABLE'
try {
  $events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop | Where-Object { $_.Id -eq 5013 -and $_.TimeCreated -ge $startedAt }
  if ($events) { $detection = 'DETECTED' } else { $detection = 'NOT_OBSERVED' }
} catch { $detection = 'UNAVAILABLE' }
if ($afterRTP -eq $true) {
  Write-Output "PASS: the unauthorized real-time-protection-disable attempt was denied -- real-time protection remained enabled. detection=$detection [BAS-SIM-AVCONFIG003]"
} elseif ($afterRTP -eq $false) {
  Write-Output "FAIL: real-time protection was actually disabled by the attempt despite Tamper Protection reporting enabled beforehand -- restored immediately. detection=$detection [BAS-SIM-AVCONFIG003]"
} else {
  Write-Output "SKIP (untested): could not determine the resulting protection state after the attempt. detection=$detection [BAS-SIM-AVCONFIG003]"
}`,
			Description:    "require an explicit human-set execution gate and a real pre-attempt Tamper-Protection/RTP status check, then attempt a permitted real-time-monitoring-disable change expecting it to be denied, unconditionally restoring the setting and re-verifying the resulting state afterward -- never attempting the change when a denial is not already the expected, safe outcome",
			CleanupCommand: `try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}`,
		},
		nil,
		"a security-tampering attempt has no benign counterpart: the test specifically isolates whether the control resists an unauthorized configuration change, which has no legitimate-activity equivalent",
		"unconditionally re-enable real-time monitoring via CleanupCommand regardless of whether the attempt succeeded or was rejected; verify via a post-test status read that protection is actually back on before considering the test complete",
		"this vector must never be dispatched against this build host, any production endpoint, or any routine/general-purpose campaign -- it is permanently excluded from internal/avscenario's dispatchableSeedVectorIDs (enforced by a cross-package regression test) and additionally requires the BAS_CONFIRM_AV_RTP_DISABLE_ATTEMPT execution gate plus a real pre-attempt precondition check, even when dispatched deliberately on an authorized lab endpoint; the EID 5013 detection check is corroborated by third-party Sigma rules and practitioner guides as Defender's Tamper-Protection-blocked-change event, but is NOT independently verified against Microsoft's own official Event ID reference -- other sources report conflicting IDs (3002, 5007, 5012) for adjacent Defender configuration events, so this detection check is best-effort and may under-report on a Defender build where the real EID differs",
		StandardsMapping{ATTACKTechniques: []string{"T1562.001"}},
		"manually authored from av.txt §2.D / §3 'Security tampering'",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}
