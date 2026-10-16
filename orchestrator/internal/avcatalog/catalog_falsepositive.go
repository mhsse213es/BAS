package avcatalog

import "github.com/audspect/bas/internal/avval"

// falsePositiveResilienceVectors seeds av.txt §2.H (False positives,
// compatibility and operational resilience). Unlike every other family,
// these vectors' Primary execution IS the legitimate workload itself --
// PrimaryClaim is avval.ClaimFalsePositive, not avval.ClaimPrevention -- so
// a product that disrupts them has produced a confirmed gap even though
// nothing malicious ever ran. "A product that blocks threats but repeatedly
// disrupts legitimate operations is not providing an acceptable enterprise
// outcome" (av.txt §2.H).
func falsePositiveResilienceVectors() ([]Vector, error) {
	var out []Vector

	v1, err := NewVector(
		"AV-FP-001", 1, FamilyFalsePositiveResilience,
		"Legitimate signed business script execution",
		SeverityLow,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"a legitimately signed internal business automation script is available and approved for this test",
		avval.ClaimFalsePositive,
		ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Set-Content -Path "$env:TEMP\avtest-business-script-marker.txt" -Value 'business script ran'`,
			ArtifactPath:   `%TEMP%\avtest-business-script-marker.txt`,
			Description:    "simulate an approved, digitally signed internal business automation script's normal benign function (a disposable marker write)",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-business-script-marker.txt" -Force -ErrorAction SilentlyContinue`,
		},
		nil,
		"this vector tests business-script tolerance directly; no adversarial counterpart is needed, since the entire point is whether legitimate activity is left alone",
		"delete the marker file written by the simulated script",
		"",
		StandardsMapping{ATTACKTechniques: []string{"T1059.001"}},
		"manually authored from av.txt §2.H",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewVector(
		"AV-FP-002", 1, FamilyFalsePositiveResilience,
		"High-I/O legitimate workload during active scanning",
		SeverityLow,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer, PlatformLinuxServer},
		[]RequiredCapability{CapabilitySignatureAV},
		"an approved high-I/O business workload (e.g. a bulk file-copy or build job) is available and approved for this test",
		avval.ClaimFalsePositive,
		ExecutionTemplate{
			Executor: "powershell",
			Command: `$dir = "$env:TEMP\avtest-highio"; New-Item -ItemType Directory -Path $dir -Force | Out-Null; ` +
				`$sw = [Diagnostics.Stopwatch]::StartNew(); ` +
				`while ($sw.Elapsed.TotalSeconds -lt 60) { 1..50 | ForEach-Object { Set-Content -Path "$dir\f$_.tmp" -Value ([guid]::NewGuid().ToString()) }; Get-ChildItem $dir | Remove-Item -Force }`,
			ArtifactPath:   `%TEMP%\avtest-highio`,
			Description:    "run a 60-second high-I/O loop writing and deleting many small disposable files in a temp directory while on-access scanning is active, to measure whether the workload is blocked, throttled past an acceptable threshold, or allowed to complete",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-highio" -Recurse -Force -ErrorAction SilentlyContinue`,
		},
		nil,
		"this vector tests operational-resilience tolerance directly; no adversarial counterpart is needed",
		"remove the disposable test directory and any files remaining in it",
		"'acceptable performance degradation' is not itself defined by this vector -- a finding here should report the observed outcome and any measured impact, leaving the acceptability threshold to the customer's own operational requirements",
		StandardsMapping{ATTACKTechniques: []string{"T1499.003"}},
		"manually authored from av.txt §2.H",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
