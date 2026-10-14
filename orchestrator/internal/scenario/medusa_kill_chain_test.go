package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMedusaKillChain_ParsesWithTenStepsWindowsOnlyFullyGrounded(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "medusa-kill-chain.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Verify 10 steps
	if len(sc.Steps) != 10 {
		t.Fatalf("got %d steps, want 10", len(sc.Steps))
	}

	// Verify Windows-only
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
		t.Fatalf("SupportedOS = %v, want [windows]", sc.SupportedOS)
	}

	// Verify technique sequence
	wantTechniques := []string{
		"T1190", "T1562.001", "T1047", "T1003.001", "T1570",
		"T1083", "T1020", "T1490", "T1489", "T1486",
	}
	if len(sc.Steps) != len(wantTechniques) {
		t.Fatalf("got %d steps, want %d", len(sc.Steps), len(wantTechniques))
	}
	for i, want := range wantTechniques {
		if got := sc.Steps[i].TechniqueID; got != want {
			t.Errorf("step %d: technique_id = %q, want %q", i, got, want)
		}
	}

	// Verify all steps have provenance fields and correct action_keys
	for i, st := range sc.Steps {
		if st.FamilyAttributionConfidence == "" {
			t.Errorf("step %d (%s): family_attribution_confidence is empty", i, st.TechniqueID)
			continue
		}
		if len(st.ThreatIntelSources) == 0 {
			t.Errorf("step %d (%s): threat_intel_sources empty", i, st.TechniqueID)
		}
		if st.LastReviewed == "" {
			t.Errorf("step %d (%s): last_reviewed empty", i, st.TechniqueID)
		}
	}

	// Verify action_key values where required
	step2 := sc.Steps[1] // T1562.001
	if step2.ActionKey != "enumerate" {
		t.Errorf("Step 2 (T1562.001): action_key = %q, want enumerate", step2.ActionKey)
	}
	step4 := sc.Steps[3] // T1003.001
	if step4.ActionKey != "handle_probe" {
		t.Errorf("Step 4 (T1003.001): action_key = %q, want handle_probe", step4.ActionKey)
	}
	step8 := sc.Steps[7] // T1490 enum
	if step8.ActionKey != "enumerate" {
		t.Errorf("Step 8 (T1490): action_key = %q, want enumerate", step8.ActionKey)
	}
	step9 := sc.Steps[8] // T1489
	if step9.ActionKey != "service_stop" {
		t.Errorf("Step 9 (T1489): action_key = %q, want service_stop", step9.ActionKey)
	}
	step10 := sc.Steps[9] // T1486
	if step10.ActionKey != "ransomware_sim_sandboxed" {
		t.Errorf("Step 10 (T1486): action_key = %q, want ransomware_sim_sandboxed", step10.ActionKey)
	}
}
