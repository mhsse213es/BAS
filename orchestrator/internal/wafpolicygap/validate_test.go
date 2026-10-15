package wafpolicygap

import "testing"

func mustScenario(t *testing.T, id string, attackVectorID string) PolicyGapScenario {
	t.Helper()
	s, err := NewPolicyGapScenario(id, WeaknessDetectionOnlyMode, attackVectorID, "x", "x", "x")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario(%q): %v", id, err)
	}
	return s
}

func TestValidatePolicyGapCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidatePolicyGapCatalog([]PolicyGapScenario{
		mustScenario(t, "GAP-001", "POLICY-001"),
		mustScenario(t, "GAP-002", "SQLI-001"),
	})
	if err != nil {
		t.Fatalf("ValidatePolicyGapCatalog: %v", err)
	}
}

func TestValidatePolicyGapCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidatePolicyGapCatalog([]PolicyGapScenario{
		mustScenario(t, "GAP-001", "POLICY-001"),
		mustScenario(t, "GAP-001", "SQLI-001"),
	})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidatePolicyGapCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidatePolicyGapCatalog(nil); err != nil {
		t.Fatalf("ValidatePolicyGapCatalog(nil): %v", err)
	}
}
