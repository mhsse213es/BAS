package wafcatalog

import "testing"

func mustVector(t *testing.T, id string) AttackVector {
	t.Helper()
	benign := validBenign()
	v, err := NewAttackVector(id, 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector(%q): %v", id, err)
	}
	return v
}

func TestValidateCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateCatalog([]AttackVector{mustVector(t, "SQLI-001"), mustVector(t, "SQLI-002")})
	if err != nil {
		t.Fatalf("ValidateCatalog: %v", err)
	}
}

func TestValidateCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateCatalog([]AttackVector{mustVector(t, "SQLI-001"), mustVector(t, "SQLI-001")})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateCatalog(nil); err != nil {
		t.Fatalf("ValidateCatalog(nil): %v", err)
	}
}
