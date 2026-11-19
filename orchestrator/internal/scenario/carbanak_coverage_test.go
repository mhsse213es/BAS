package scenario

import "testing"

// Regression guard: the two no_clean_attack_technique steps (items 23 and 28)
// must not count toward ATT&CK technique coverage.
func TestCarbanakGapStepsExcludedFromCoverage(t *testing.T) {
	var steps []ScenarioStep
	for _, file := range []string{
		"carbanak-kill-chain.yaml",
		"carbanak-bfsi-beneficiary-creation.yaml",
		"carbanak-bfsi-limit-modification.yaml",
	} {
		sc := loadBFSIScenario(t, file)
		for _, st := range sc.Steps {
			steps = append(steps, ScenarioStep{TaskID: st.Name, TechniqueID: st.TechniqueID})
		}
	}

	distinct := map[string]struct{}{}
	empty := 0
	for _, s := range steps {
		if s.TechniqueID == "" {
			empty++
			continue
		}
		distinct[s.TechniqueID] = struct{}{}
	}
	if empty != 5 {
		t.Fatalf("technique-less steps = %d, want 5 (chain 8b, 8f, 8g; items 23 and 28)", empty)
	}

	_, cov := SelectRepresentative(steps, RepresentativeLimits{PerTechnique: 1})
	if cov.TechniquesTotal != len(distinct) {
		t.Fatalf("TechniquesTotal = %d, want %d distinct non-empty IDs", cov.TechniquesTotal, len(distinct))
	}
}
