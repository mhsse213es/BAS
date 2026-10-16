package avcatalog

import "github.com/audspect/bas/internal/avval"

// behavioralVectors seeds av.txt §2.C (Behavioral detection and exploit
// prevention): process-injection-pattern and suspicious-child-process-chain
// simulations, separated from EDR-specific investigation/response
// capabilities (av.txt §2.C closing note).
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
			Executor: "binary", Command: "avtest-injector.exe --target=disposable-test-process --payload=benign-marker",
			Description: "launch a purpose-built test harness that performs a benign process-injection-pattern simulation into a disposable test process it spawns itself, never a production process",
		},
		nil,
		"process-injection APIs have no close legitimate business counterpart suitable for a false-positive comparison in this vector; legitimate-tooling false-positive resilience for injection-adjacent techniques (debuggers, EDR agents themselves) is covered separately under §2.H",
		"terminate the disposable test process and confirm no injected artifact persists",
		"this vector's Primary.Command names a purpose-built test harness binary (avtest-injector.exe) that does not exist yet -- it is not concretely dispatchable through the standard powershell/cmd executors until that harness is built; it remains valid for fixture-backed avval/avefficacy evaluation today",
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
