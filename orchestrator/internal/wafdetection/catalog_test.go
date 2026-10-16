package wafdetection

import "testing"

func TestAudspectWAFDetectionCatalog_ReturnsFiveScenariosTotal(t *testing.T) {
	completeness, alert, timing, err := AudspectWAFDetectionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFDetectionCatalog: %v", err)
	}
	total := len(completeness) + len(alert) + len(timing)
	if total != 5 {
		t.Fatalf("total scenarios = %d, want 5 (got completeness=%d, alert=%d, timing=%d)", total, len(completeness), len(alert), len(timing))
	}
	if len(completeness) != 3 {
		t.Errorf("len(completeness) = %d, want 3", len(completeness))
	}
	if len(alert) != 1 {
		t.Errorf("len(alert) = %d, want 1", len(alert))
	}
	if len(timing) != 1 {
		t.Errorf("len(timing) = %d, want 1", len(timing))
	}
}

// Review Focus: the 3 completeness scenarios must cover exactly the 3
// intended channels, not accidentally duplicate one. ChannelAlertQueue is
// deliberately NOT used by any completeness scenario -- alerts are
// covered by the separate AlertScenario shape -- so its absence here is
// correct, not a gap.
func TestAudspectWAFDetectionCatalog_CompletenessScenariosCoverExactlyThreeChannels(t *testing.T) {
	completeness, _, _, err := AudspectWAFDetectionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFDetectionCatalog: %v", err)
	}
	seen := make(map[EvidenceChannel]int)
	for _, s := range completeness {
		seen[s.Channel]++
	}
	want := []EvidenceChannel{ChannelWAFEventLog, ChannelSIEMRecord, ChannelEvidenceArchive}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("channel %q appears %d times in the completeness catalog, want exactly 1", w, seen[w])
		}
	}
	if seen[ChannelAlertQueue] != 0 {
		t.Errorf("ChannelAlertQueue appears %d times in the completeness catalog, want 0 (alerts are covered by AlertScenario, not CompletenessScenario)", seen[ChannelAlertQueue])
	}
	if len(seen) != 3 {
		t.Errorf("completeness catalog covers %d distinct channels, want exactly 3", len(seen))
	}
}
