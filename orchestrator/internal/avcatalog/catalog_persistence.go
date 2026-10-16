package avcatalog

import "github.com/audspect/bas/internal/avval"

// credentialPersistenceVectors seeds av.txt §2.G (Credential, persistence
// and lateral-movement indicators): unauthorized startup/persistence
// mechanisms and harmless credential-access-pattern simulations, validated
// without establishing real unauthorized persistence or extracting real
// credentials.
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
			Executor:       "powershell",
			Command:        `New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'AVTestMarker' -Value 'cmd.exe /c exit' -Force`,
			Description:    "add a disposable test value to the current user's Run key, whose command only performs a no-op exit -- never a real malicious payload or a system-wide (HKLM) key",
			CleanupCommand: `Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'AVTestMarker' -Force -ErrorAction SilentlyContinue`,
		},
		&ExecutionTemplate{
			Executor:       "powershell",
			Command:        `New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'AVTestLegitInstaller' -Value 'cmd.exe /c exit' -Force`,
			Description:    "simulate a legitimate software installer adding its own Run-key entry during a normal install flow, proving the control is not flagging Run-key writes universally",
			CleanupCommand: `Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'AVTestLegitInstaller' -Force -ErrorAction SilentlyContinue`,
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
			Executor:       "cmd",
			Command:        `schtasks /create /tn "AVTestMarkerTask" /tr "cmd.exe /c exit" /sc onlogon /f`,
			Description:    "create a disposable test scheduled task that runs at logon, whose action is a no-op exit",
			CleanupCommand: `schtasks /delete /tn "AVTestMarkerTask" /f`,
		},
		&ExecutionTemplate{
			Executor:       "cmd",
			Command:        `schtasks /create /tn "AVTestLegitUpdaterTask" /tr "cmd.exe /c exit" /sc onlogon /f`,
			Description:    "simulate a legitimate software updater creating its own scheduled task during a normal update flow",
			CleanupCommand: `schtasks /delete /tn "AVTestLegitUpdaterTask" /f`,
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

	v3, err := NewVector(
		"AV-CREDACCESS-001", 1, FamilyCredentialPersistence,
		"Benign simulation of a credential-store process-access pattern",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has a behavioral/NGAV engine capable of process-access-pattern inspection; lsass.exe is present (default on Windows)",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Get-Process -Name lsass | ForEach-Object { $_.Handle } | Out-Null`,
			Description:    "open a handle to the lsass.exe process without reading any memory or extracting any credential material -- only the minimal process-access pattern behavioral engines look for, never an actual credential dump",
			CleanupCommand: "",
		},
		&ExecutionTemplate{
			Executor:    "powershell",
			Command:     `Get-Process -Name explorer | ForEach-Object { $_.Handle } | Out-Null`,
			Description: "open the identical kind of process handle against an ordinary, non-sensitive process, proving the control is not flagging process-handle access universally",
		},
		"",
		"neither leg leaves a persistent artifact; no cleanup is required",
		"this vector deliberately never reads process memory or extracts real credential material, to avoid any risk of actual credential exposure -- it measures only whether the access PATTERN (opening a handle to lsass.exe) is itself flagged, not a full LSASS-dump simulation",
		StandardsMapping{ATTACKTechniques: []string{"T1003.001"}},
		"manually authored from av.txt §2.G 'harmless simulations of suspicious credential-access behavior'",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}
