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
			Executor: "powershell", Command: "Invoke-ApprovedBusinessScript.ps1",
			Description: "run an approved, digitally signed internal business automation script performing its normal benign function",
		},
		nil,
		"this vector tests business-script tolerance directly; no adversarial counterpart is needed, since the entire point is whether legitimate activity is left alone",
		"none -- the script performs no persistent side effect by design",
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
			Executor: "binary", Command: "avtest-highio-workload-sim.exe --duration=60s",
			Description: "run an approved high-CPU/high-I/O business workload simulation while on-access scanning is active, to measure whether the workload is blocked, throttled past an acceptable threshold, or allowed to complete",
		},
		nil,
		"this vector tests operational-resilience tolerance directly; no adversarial counterpart is needed",
		"none -- the simulated workload writes only to a disposable test directory, removed at completion",
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
