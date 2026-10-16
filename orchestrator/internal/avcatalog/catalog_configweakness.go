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

	v3, err := NewVector(
		"AV-CONFIG-003", 1, FamilyConfigurationWeakness,
		"Attempt to disable real-time protection via an unauthorized path",
		SeverityCritical,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has tamper protection enabled; this vector must only run on a dedicated, non-production test endpoint, never a build or production host -- its CleanupCommand unconditionally attempts to restore real-time protection regardless of outcome",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Set-MpPreference -DisableRealtimeMonitoring $true`,
			Description:    "attempt a permitted, harmless security-setting modification (disabling real-time monitoring) to measure whether tamper protection rejects the change and records the attempt",
			CleanupCommand: `Set-MpPreference -DisableRealtimeMonitoring $false`,
		},
		nil,
		"a security-tampering attempt has no benign counterpart: the test specifically isolates whether the control resists an unauthorized configuration change, which has no legitimate-activity equivalent",
		"unconditionally re-enable real-time monitoring via CleanupCommand regardless of whether the attempt succeeded or was rejected; verify via a post-test status read that protection is actually back on before considering the test complete",
		"this vector must never be dispatched against this build host or any production endpoint; it is authored for a dedicated, isolated test lab only",
		StandardsMapping{ATTACKTechniques: []string{"T1562.001"}},
		"manually authored from av.txt §2.D / §3 'Security tampering'",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}
