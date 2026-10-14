package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlackBastaKillChain_ParsesWithTenStepsWindowsOnlyFullyGrounded(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "black-basta-kill-chain.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
		t.Fatalf("SupportedOS = %v, want [windows]", sc.SupportedOS)
	}
	wantTechniques := []string{
		"T1566.001", "T1003.001", "T1562.001", "T1543.003", "T1021.002",
		"T1083", "T1567.002", "T1486", "T1490", "T1490",
	}
	if len(sc.Steps) != len(wantTechniques) {
		t.Fatalf("got %d steps, want %d", len(sc.Steps), len(wantTechniques))
	}
	for i, want := range wantTechniques {
		if got := sc.Steps[i].TechniqueID; got != want {
			t.Errorf("step %d: technique_id = %q, want %q", i, got, want)
		}
	}
	for i, st := range sc.Steps {
		if st.FamilyAttributionConfidence == "" {
			t.Errorf("step %d (%s): family_attribution_confidence is empty -- every technique-tagged step in this scenario must have real grounding", i, st.TechniqueID)
			continue
		}
		if len(st.ThreatIntelSources) == 0 {
			t.Errorf("step %d (%s): family_attribution_confidence=%q but threat_intel_sources is empty", i, st.TechniqueID, st.FamilyAttributionConfidence)
		}
		if st.FamilyAttributionConfidence == FamilyAttributionConfirmed && len(st.ThreatIntelSources) < 2 {
			t.Errorf("step %d (%s): confirmed with only %d source(s) -- contentregistry's structural check requires >=2", i, st.TechniqueID, len(st.ThreatIntelSources))
		}
		if st.LastReviewed == "" {
			t.Errorf("step %d (%s): last_reviewed is empty", i, st.TechniqueID)
		}
	}
}
