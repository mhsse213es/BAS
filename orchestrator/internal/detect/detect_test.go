package detect

import "testing"

func TestIsEDRProvider(t *testing.T) {
	hits := []string{"Microsoft Defender Antivirus", "Trellix Endpoint Security",
		"CrowdStrike Falcon Sensor", "SentinelOne Agent", "Sophos Intercept X",
		"Trend Micro Apex One", "Cortex XDR", "Elastic Endpoint", "FortiEDR"}
	for _, p := range hits {
		if !IsEDRProvider(p) {
			t.Errorf("expected EDR provider match: %q", p)
		}
	}
	for _, p := range []string{"Microsoft-Windows-Kernel-General", "Service Control Manager"} {
		if IsEDRProvider(p) {
			t.Errorf("unexpected EDR match: %q", p)
		}
	}
}
