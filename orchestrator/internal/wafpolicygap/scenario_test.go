package wafpolicygap

import "testing"

func TestNewPolicyGapScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001",
		"OWASP CRS default anomaly-scoring mode, rule set enabled",
		"the matching rule for this payload was switched to detection-only (log, no block)",
		"manually authored")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario: %v", err)
	}
	if s.ID != "GAP-001" {
		t.Errorf("ID = %q, want %q", s.ID, "GAP-001")
	}
}

func TestNewPolicyGapScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("", WeaknessDetectionOnlyMode, "POLICY-001", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewPolicyGapScenario_UnknownWeakness_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessType("bogus_weakness"), "POLICY-001", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for unknown Weakness, got nil")
	}
}

// Review Focus: an AttackVectorID referencing a non-existent vector must be
// rejected at construction, not silently carried to evaluation time.
func TestNewPolicyGapScenario_UnknownAttackVectorID_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "FAKE-999", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for an AttackVectorID that does not exist in wafcatalog, got nil")
	}
}

func TestNewPolicyGapScenario_EmptyBaselineDesc_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001", "", "x", "x")
	if err == nil {
		t.Fatal("want error for empty BaselinePolicyDescription, got nil")
	}
}

func TestNewPolicyGapScenario_EmptyWeakenedDesc_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001", "x", "", "x")
	if err == nil {
		t.Fatal("want error for empty WeakenedPolicyDescription, got nil")
	}
}

func TestNewPolicyGapScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001", "x", "x", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestWeaknessType_IsPaired(t *testing.T) {
	paired := []WeaknessType{WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException, WeaknessPriorityConflict}
	for _, w := range paired {
		if !w.IsPaired() {
			t.Errorf("%q.IsPaired() = false, want true", w)
		}
	}
	singleLeg := []WeaknessType{WeaknessUnprotectedRoute, WeaknessMissingCoverage}
	for _, w := range singleLeg {
		if w.IsPaired() {
			t.Errorf("%q.IsPaired() = true, want false", w)
		}
	}
}
