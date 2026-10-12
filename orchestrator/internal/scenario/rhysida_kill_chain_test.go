package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRhysidaKillChain_ParsesWithElevenStepsWindowsOnlyFullyGrounded(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "rhysida-kill-chain.yaml"))
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
		"T1078",     // Step 1: Valid Accounts
		"T1021.001", // Step 2: RDP
		"T1003.001", // Step 3: LSASS handle probe
		"T1087.002", // Step 4: Domain account discovery
		"T1562.001", // Step 5: SILENTKILL process termination
		"T1562.008", // Step 6: Event logging disable
		"T1070.001", // Step 7: Log clearing
		"T1490",     // Step 8: Recovery inhibition enum
		"T1490",     // Step 9: Recovery inhibition delete
		"T1020",     // Step 10: Exfiltration
		"T1486",     // Step 11: Encryption
	}
	if len(sc.Steps) != len(wantTechniques) {
		t.Fatalf("got %d steps, want %d", len(sc.Steps), len(wantTechniques))
	}
	for i, want := range wantTechniques {
		if got := sc.Steps[i].TechniqueID; got != want {
			t.Errorf("step %d: technique_id = %q, want %q", i, got, want)
		}
	}

	// Verify action_keys for key steps
	wantActionKeys := map[int]string{
		4: "enumerate",                                          // T1562.001
		5: "enumerate",                                          // T1562.008
		6: "enumerate",                                          // T1070.001
		7: "enumerate",                                          // T1490 enum
		8: "ransomware_sim_sandboxed",                           // T1490 delete (could also be service_stop)
		10: "ransomware_sim_sandboxed",                          // T1486
	}
	for stepIdx, wantKey := range wantActionKeys {
		gotKey := sc.Steps[stepIdx].ActionKey
		if stepIdx == 8 {
			// T1490 delete: accept either service_stop or ransomware_sim_sandboxed
			if gotKey != "service_stop" && gotKey != "ransomware_sim_sandboxed" {
				t.Errorf("step %d (T1490 delete): action_key = %q, want 'service_stop' or 'ransomware_sim_sandboxed'", stepIdx, gotKey)
			}
		} else if gotKey != wantKey {
			t.Errorf("step %d: action_key = %q, want %q", stepIdx, gotKey, wantKey)
		}
	}

	// Verify provenance fields
	for i, st := range sc.Steps {
		if st.FamilyAttributionConfidence == "" {
			t.Errorf("step %d (%s): family_attribution_confidence is empty -- every technique-tagged step must have real grounding", i, st.TechniqueID)
			continue
		}
		if len(st.ThreatIntelSources) == 0 {
			t.Errorf("step %d (%s): family_attribution_confidence=%q but threat_intel_sources is empty", i, st.TechniqueID, st.FamilyAttributionConfidence)
		}
		if st.FamilyAttributionConfidence == FamilyAttributionConfirmed && len(st.ThreatIntelSources) < 2 {
			t.Errorf("step %d (%s): confirmed with only %d source(s) -- requires >=2", i, st.TechniqueID, len(st.ThreatIntelSources))
		}
		if st.LastReviewed == "" {
			t.Errorf("step %d (%s): last_reviewed is empty", i, st.TechniqueID)
		}
	}
}
