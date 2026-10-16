package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func TestNewEnterpriseScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewEnterpriseScenario("", "n", "o", []string{"V-1"}, "p", "e", "prov")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewEnterpriseScenario_EmptyContributingVectorIDs_Rejected(t *testing.T) {
	_, err := NewEnterpriseScenario("S-1", "n", "o", nil, "p", "e", "prov")
	if err == nil {
		t.Fatal("want error for empty contributingVectorIDs, got nil")
	}
}

func TestNewEnterpriseScenario_EmptyVectorIDEntry_Rejected(t *testing.T) {
	_, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", ""}, "p", "e", "prov")
	if err == nil {
		t.Fatal("want error for empty vector ID entry, got nil")
	}
}

func TestNewEnterpriseScenario_DuplicateVectorID_Rejected(t *testing.T) {
	_, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", "V-1"}, "p", "e", "prov")
	if err == nil {
		t.Fatal("want error for duplicate vector ID, got nil")
	}
}

func TestNewEnterpriseScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	if s.ID != "S-1" {
		t.Errorf("ID = %q, want %q", s.ID, "S-1")
	}
}

func mustVector(t *testing.T, id string) wafcatalog.AttackVector {
	t.Helper()
	v, err := wafcatalog.NewAttackVector(id, 1, wafcatalog.FamilySQLInjection, "x", wafcatalog.SeverityCritical, "x",
		wafcatalog.RequestTemplate{Method: "GET", Path: "/x", PayloadLocation: "query:q", Payload: "x", Description: "x"},
		nil, "no benign needed for this test", wafcatalog.StandardsMapping{CWEIDs: []string{"CWE-89"}}, "test")
	if err != nil {
		t.Fatalf("wafcatalog.NewAttackVector(%q): %v", id, err)
	}
	return v
}

func TestValidateAgainstCatalog_MissingVectorID_Rejected(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{mustVector(t, "V-1")}
	if err := ValidateAgainstCatalog(scenario, catalog); err == nil {
		t.Fatal("want error for scenario referencing a vector ID absent from the catalog, got nil")
	}
}

func TestValidateAgainstCatalog_AllPresent_Succeeds(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{mustVector(t, "V-1"), mustVector(t, "V-2")}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		t.Fatalf("ValidateAgainstCatalog: %v", err)
	}
}
