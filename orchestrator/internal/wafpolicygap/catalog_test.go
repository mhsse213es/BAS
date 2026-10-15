package wafpolicygap

import "testing"

func TestAudspectWAFPolicyGapCatalog_ReturnsSixScenarios(t *testing.T) {
	scenarios, err := AudspectWAFPolicyGapCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFPolicyGapCatalog: %v", err)
	}
	if len(scenarios) != 6 {
		t.Fatalf("len(scenarios) = %d, want 6", len(scenarios))
	}
	if err := ValidatePolicyGapCatalog(scenarios); err != nil {
		t.Errorf("ValidatePolicyGapCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 6 distinct weakness types, not
// duplicate one and skip another.
func TestAudspectWAFPolicyGapCatalog_CoversAllSixWeaknessTypes(t *testing.T) {
	scenarios, err := AudspectWAFPolicyGapCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFPolicyGapCatalog: %v", err)
	}
	want := []WeaknessType{
		WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException,
		WeaknessPriorityConflict, WeaknessUnprotectedRoute, WeaknessMissingCoverage,
	}
	seen := make(map[WeaknessType]int)
	for _, s := range scenarios {
		seen[s.Weakness]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("weakness %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}
