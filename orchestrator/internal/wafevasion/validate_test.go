package wafevasion

import "testing"

func mustScenario(t *testing.T, id string, attackVectorID string) EvasionScenario {
	t.Helper()
	s, err := NewEvasionScenario(id, EvasionEncodingObfuscation, attackVectorID, "x", "x", "x", "x")
	if err != nil {
		t.Fatalf("NewEvasionScenario(%q): %v", id, err)
	}
	return s
}

func TestValidateEvasionCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateEvasionCatalog([]EvasionScenario{
		mustScenario(t, "EVADE-001", "SQLI-002"),
		mustScenario(t, "EVADE-002", "PATHTRAV-001"),
	})
	if err != nil {
		t.Fatalf("ValidateEvasionCatalog: %v", err)
	}
}

func TestValidateEvasionCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateEvasionCatalog([]EvasionScenario{
		mustScenario(t, "EVADE-001", "SQLI-002"),
		mustScenario(t, "EVADE-001", "PATHTRAV-001"),
	})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateEvasionCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateEvasionCatalog(nil); err != nil {
		t.Fatalf("ValidateEvasionCatalog(nil): %v", err)
	}
}
