package avcatalog

import "github.com/audspect/bas/internal/avval"

// fileBasedVectors seeds av.txt §2.A (File-based threats): known test
// artifacts, archive scanning, and the quarantine/remediation side of the
// program, using harmless approved test artifacts rather than live malware.
func fileBasedVectors() ([]Vector, error) {
	var out []Vector

	v1, err := NewVector(
		"AV-FILE-001", 1, FamilyFileBasedThreat,
		"Known test artifact via a user-writable download/temp directory",
		SeverityCritical,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer, PlatformLinuxServer, PlatformMacOS},
		[]RequiredCapability{CapabilitySignatureAV},
		"endpoint has signature-based scanning enabled and a user-writable temp/download directory",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Set-Content -Path "$env:TEMP\avtest-eicar.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'`,
			ArtifactPath:   `%TEMP%\avtest-eicar.txt`,
			Description:    "write the industry-standard EICAR anti-malware test string to a user-writable temp path, using an approved test artifact rather than live malware",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-eicar.txt" -Force -ErrorAction SilentlyContinue`,
		},
		&ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Set-Content -Path "$env:TEMP\avtest-benign.txt" -Value 'This is an ordinary harmless test file.'`,
			ArtifactPath:   `%TEMP%\avtest-benign.txt`,
			Description:    "write an ordinary harmless text file to the same directory, proving the AV is not merely blocking by location",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-benign.txt" -Force -ErrorAction SilentlyContinue`,
		},
		"",
		"delete the dropped test file and confirm no quarantine entry or residual copy remains",
		"a product that only scans on-access, not on-write, may legitimately show no detection until the file is subsequently opened -- this is a product-capability limitation, not necessarily a gap",
		StandardsMapping{ATTACKTechniques: []string{"T1204.002"}},
		"manually authored from av.txt §2.A",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewVector(
		"AV-FILE-002", 1, FamilyFileBasedThreat,
		"Nested archive containing a known test artifact",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilitySignatureAV},
		"endpoint has signature-based scanning enabled",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "powershell",
			Command: `Set-Content -Path "$env:TEMP\avtest-eicar-nested.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'; ` +
				`Compress-Archive -Path "$env:TEMP\avtest-eicar-nested.txt" -DestinationPath "$env:TEMP\avtest-archive.zip" -Force`,
			ArtifactPath:   `%TEMP%\avtest-archive.zip`,
			Description:    "write the EICAR test string to a temp file, then compress it into a zip archive in a user-writable temp path, to exercise extraction-time (not just at-rest) scanning",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-eicar-nested.txt","$env:TEMP\avtest-archive.zip" -Force -ErrorAction SilentlyContinue`,
		},
		nil,
		"a nested archive has no meaningful benign counterpart for this vector: the test specifically isolates whether extraction-time (rather than at-rest) scanning catches content inside an archive",
		"delete the archive and the source file that was compressed into it; confirm no quarantine entry or residual extracted artifact remains",
		"this vector exercises nested-archive scanning, not password-protected archive scanning: PowerShell's native Compress-Archive has no password support, so a genuinely password-protected variant would require an approved third-party archive utility not scripted here",
		StandardsMapping{ATTACKTechniques: []string{"T1027.002"}},
		"manually authored from av.txt §2.A",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
