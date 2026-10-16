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
			Executor: "powershell", Command: "powershell.exe -EncodedCommand <base64 of a harmless marker-file write>",
			Description: "run a base64-encoded PowerShell one-liner mimicking a common encoded-command evasion pattern, whose actual payload only writes a harmless marker file",
		},
		&ExecutionTemplate{
			Executor: "powershell", Command: "powershell.exe -Command \"<same marker-file write, unencoded>\"",
			Description: "run the identical marker-file-write action via a plain, unencoded PowerShell command, proving the control is not simply penalizing PowerShell execution generally",
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
			Executor: "cmd", Command: `certutil.exe -urlcache -split -f http://127.0.0.1:0/avtest-marker http://avtest-marker.local`,
			Description: "invoke certutil.exe's undocumented download capability against a local, non-routable test endpoint, mimicking LOLBin-based file retrieval without actually retrieving or executing any payload",
		},
		nil,
		"certutil's URL-fetch capability has no close legitimate business counterpart in typical endpoint workflows that would need to be distinguished here; genuine administrative certificate operations are a different command surface entirely",
		"no artifact is created by this vector; confirm no residual cached file remains from the attempted fetch",
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
