package dlpprofile

import "testing"

func TestRealDLPScenarioIDs_ReturnsExactlyTheRealIDs(t *testing.T) {
	ids := RealDLPScenarioIDs()
	want := []string{
		"dlp-exfiltration-validation",
		"dlp-exfiltration-sink-https",
		"dlp-exfiltration-dns-tunnel",
		"dlp-exfiltration-sftp",
		"dlp-exfiltration-smtp",
		"dlp-exfiltration-cloud-storage",
		"dlp-exfiltration-webhook",
		"dlp-exfiltration-coderepo",
		"dlp-exfiltration-telnet",
		"dlp-exfiltration-multichannel",
		"dlp-exfiltration-ai-prompt",
		"dlp-exfiltration-db-export",
		"dlp-exfiltration-devtools",
		"dlp-exfiltration-email-recipients",
		"dlp-exfiltration-archive-transfer",
		"dlp-exfiltration-web-upload",
		"dlp-exfiltration-network-share",
		"dlp-exfiltration-device-control",
		"dlp-exfiltration-lateral-movement",
	}
	if len(ids) != len(want) {
		t.Fatalf("len(ids) = %d, want %d", len(ids), len(want))
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing expected scenario ID %q", w)
		}
	}
}
