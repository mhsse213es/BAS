package avcatalog

import "github.com/audspect/bas/internal/avval"

// scriptFilelessVectors seeds av.txt §2.B (Script, interpreter and fileless
// threats): encoded-command execution and LOLBin abuse, using benign,
// purpose-built simulations rather than real payloads or exploit chains.
func scriptFilelessVectors() ([]Vector, error) {
	var out []Vector

	v1, err := NewVector(
		"AV-SCRIPT-001", 1, FamilyScriptFileless,
		"Encoded PowerShell command execution",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has a behavioral/NGAV engine capable of script-content inspection",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "powershell",
			Command: `$inner = 'Set-Content -Path "$env:TEMP\avtest-script-marker.txt" -Value marker'; ` +
				`$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner)); ` +
				`powershell.exe -NoProfile -EncodedCommand $enc`,
			ArtifactPath:   `%TEMP%\avtest-script-marker.txt`,
			Description:    "run a base64-encoded PowerShell one-liner mimicking a common encoded-command evasion pattern, whose actual payload only writes a harmless marker file",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-script-marker.txt" -Force -ErrorAction SilentlyContinue`,
		},
		&ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Set-Content -Path "$env:TEMP\avtest-script-marker.txt" -Value 'marker'`,
			ArtifactPath:   `%TEMP%\avtest-script-marker.txt`,
			Description:    "run the identical marker-file-write action via a plain, unencoded PowerShell command, proving the control is not simply penalizing PowerShell execution generally",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-script-marker.txt" -Force -ErrorAction SilentlyContinue`,
		},
		"",
		"delete the marker file written by either leg",
		"",
		StandardsMapping{ATTACKTechniques: []string{"T1059.001", "T1140"}},
		"manually authored from av.txt §2.B",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewVector(
		"AV-SCRIPT-002", 1, FamilyScriptFileless,
		"LOLBin abuse: certutil used for file transfer instead of its intended certificate role",
		SeverityMedium,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilityBehavioralNGAV},
		"endpoint has a behavioral/NGAV engine capable of process-behavior inspection; certutil.exe is present (default on Windows)",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor:       "cmd",
			Command:        `certutil.exe -urlcache -split -f "http://127.0.0.1:1/avtest-marker" "%TEMP%\avtest-certutil-fetch.tmp"`,
			ArtifactPath:   `%TEMP%\avtest-certutil-fetch.tmp`,
			Description:    "invoke certutil.exe's undocumented download capability against an unreachable loopback port (connection refused immediately, nothing ever fetched), mimicking LOLBin-based file retrieval without actually retrieving or executing any payload",
			CleanupCommand: `del "%TEMP%\avtest-certutil-fetch.tmp" 2>nul`,
		},
		nil,
		"certutil's URL-fetch capability has no close legitimate business counterpart in typical endpoint workflows that would need to be distinguished here; genuine administrative certificate operations are a different command surface entirely",
		"delete any residual (likely empty or absent) cache file certutil may have created from the failed fetch attempt",
		"",
		StandardsMapping{ATTACKTechniques: []string{"T1105", "T1218.011"}},
		"manually authored from av.txt §2.B",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
