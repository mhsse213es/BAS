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
			Executor: "file_drop", Command: "write_eicar_test_string",
			ArtifactPath: "%TEMP%/avtest-eicar.txt",
			Description:  "write the industry-standard EICAR anti-malware test string to a user-writable temp path, using an approved test artifact rather than live malware",
		},
		&ExecutionTemplate{
			Executor: "file_drop", Command: "write_benign_textfile",
			ArtifactPath: "%TEMP%/avtest-benign.txt",
			Description:  "write an ordinary harmless text file to the same directory, proving the AV is not merely blocking by location",
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
		"Password-protected archive containing a known test artifact",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation, PlatformWindowsServer},
		[]RequiredCapability{CapabilitySignatureAV},
		"endpoint has signature-based scanning enabled; a password-protected archive utility is available",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor: "file_drop", Command: "write_password_protected_archive_with_eicar",
			ArtifactPath: "%TEMP%/avtest-archive.zip",
			Description:  "write a password-protected zip archive containing the EICAR test string to a user-writable temp path",
		},
		nil,
		"password-protected archives have no meaningful benign counterpart for this vector: the test specifically isolates whether extraction-time (rather than at-rest) scanning catches content a product cannot read without the password",
		"delete the archive and any extracted copies; confirm no quarantine entry or residual extracted artifact remains",
		"many products cannot scan inside a password-protected archive until extraction; an Inconclusive or untested-capability result here is an expected, acceptable outcome, not evidence of a gap, unless the product specifically advertises password-protected archive scanning",
		StandardsMapping{ATTACKTechniques: []string{"T1027.002"}},
		"manually authored from av.txt §2.A",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
