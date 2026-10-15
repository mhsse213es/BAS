package wafapiflow

import "testing"

func mustVector(t *testing.T, id string) APIFlowVector {
	t.Helper()
	benign := validBenign()
	v, err := NewAPIFlowVector(id, 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAPIFlowVector(%q): %v", id, err)
	}
	return v
}

func TestValidateAPIFlowCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateAPIFlowCatalog([]APIFlowVector{mustVector(t, "APIFLOW-001"), mustVector(t, "APIFLOW-002")})
	if err != nil {
		t.Fatalf("ValidateAPIFlowCatalog: %v", err)
	}
}

func TestValidateAPIFlowCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateAPIFlowCatalog([]APIFlowVector{mustVector(t, "APIFLOW-001"), mustVector(t, "APIFLOW-001")})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateAPIFlowCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateAPIFlowCatalog(nil); err != nil {
		t.Fatalf("ValidateAPIFlowCatalog(nil): %v", err)
	}
}
