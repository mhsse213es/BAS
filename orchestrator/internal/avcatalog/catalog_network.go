package avcatalog

import "github.com/audspect/bas/internal/avval"

// networkDeliveredVectors seeds av.txt §2.E (Network-delivered threats):
// browser-download delivery of a known test artifact. This vector exists
// specifically to exercise the attribution discipline av.txt §4 requires --
// "measure what the AV/NGAV actually controls. Attribute DNS, web-gateway,
// firewall and proxy blocks to those products instead of incorrectly
// crediting the antivirus" -- which avval's ControlSource makes possible: a
// network-layer block (ControlSourceNetworkControl) must never be credited
// to the AV engine (ControlSourceAVEngine).
func networkDeliveredVectors() ([]Vector, error) {
	var out []Vector

	v1, err := NewVector(
		"AV-NET-001", 1, FamilyNetworkDelivered,
		"HTTP download of a known test artifact",
		SeverityHigh,
		[]Platform{PlatformWindowsWorkstation},
		[]RequiredCapability{CapabilitySignatureAV, CapabilityNetworkControl},
		"endpoint has outbound HTTP access to a controlled test host serving the artifact -- deploying that controlled host is an environment precondition, the same category of setup as a lab endpoint for the real end-to-end vertical",
		avval.ClaimPrevention,
		ExecutionTemplate{
			Executor:       "powershell",
			Command:        `Invoke-WebRequest -Uri "http://avtest-host.local/eicar-test.txt" -OutFile "$env:TEMP\avtest-network-download.txt" -UseBasicParsing`,
			ArtifactPath:   `%TEMP%\avtest-network-download.txt`,
			Description:    "download the EICAR test artifact over plain HTTP to a user-writable temp path, to exercise download-time scanning and any web-gateway/network control that may intercept the request first",
			CleanupCommand: `Remove-Item -Path "$env:TEMP\avtest-network-download.txt" -Force -ErrorAction SilentlyContinue`,
		},
		nil,
		"an HTTP-mediated download has no distinct benign counterpart needed for this vector: the comparable legitimate-download false-positive case is the same download flow with an ordinary file, already covered by AV-FILE-001's benign leg",
		"delete the downloaded file and confirm no quarantine entry or residual copy remains",
		"this vector exercises the download mechanism via Invoke-WebRequest, not literal browser-UI-mediated download; macOS coverage would need a native curl/shell-based variant, not yet authored, so macOS is deliberately excluded from Platforms until then. If a network/web-gateway control intercepts the request before it reaches the endpoint, Execution/Prevention evidence from the AV engine itself may legitimately show no observation at all -- this must be attributed to the network control via its own ControlSource, never silently credited to the AV engine",
		StandardsMapping{ATTACKTechniques: []string{"T1105", "T1071.001"}},
		"manually authored from av.txt §2.E",
	)
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	return out, nil
}
