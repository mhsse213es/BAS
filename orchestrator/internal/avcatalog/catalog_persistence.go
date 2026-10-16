package avcatalog

import "github.com/audspect/bas/internal/avval"

// credentialPersistenceVectors seeds av.txt §2.G (Credential, persistence
// and lateral-movement indicators): unauthorized startup/persistence
// mechanisms, validated without establishing real unauthorized persistence.
func credentialPersistenceVectors() ([]Vector, error) {
	var out []Vector

	v1, err := NewVector(
		"AV-PERSIST-001", 1, FamilyCredentialPersistence,
		"Unauthorized Run-key persistence simulation",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has a behavioral/NGAV engine capable of registry-write inspection; a disposable test Run-key value name is available",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "powershell", Command: `New-ItemProperty -Path 'HKCU:\...\Run' -Name 'AVTestMarker' -Value '<benign marker command>'`,
			Description: "add a disposable test value to the current user's Run key, whose command only performs a benign marker write -- never a real malicious payload or a system-wide (HKLM) key",
		},
		&ExecutionTemplate{
			Executor: "binary", Command: "avtest-installer-sim.exe --install-runkey-entry",
			Description: "simulate a legitimate software installer adding its own Run-key entry during a normal install flow, proving the control is not flagging Run-key writes universally",
		},
		"",
		"remove the test Run-key value added by either leg",
		"",
		StandardsMapping{ATTACKTechniques: []string{"T1547.001"}},
		"manually authored from av.txt §2.G",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewVector(
		"AV-PERSIST-002", 1, FamilyCredentialPersistence,
		"Suspicious scheduled task creation simulation",
		SeverityMedium,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has a behavioral/NGAV engine capable of scheduled-task-creation inspection",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "cmd", Command: `schtasks /create /tn "AVTestMarkerTask" /tr "<benign marker command>" /sc onlogon`,
			Description: "create a disposable test scheduled task that runs at logon, whose action only performs a benign marker write",
		},
		&ExecutionTemplate{
			Executor: "binary", Command: "avtest-updater-sim.exe --install-scheduled-task",
			Description: "simulate a legitimate software updater creating its own scheduled task during a normal update flow",
		},
		"",
		"remove the test scheduled task created by either leg",
		"",
		StandardsMapping{ATTACKTechniques: []string{"T1053.005"}},
		"manually authored from av.txt §2.G",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
