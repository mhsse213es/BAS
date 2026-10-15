package wafapiflow

import "testing"

func validMalicious() RequestTemplate {
	return RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": -1}`, Description: "negative-quantity checkout abuse"}
}

func validBenign() RequestTemplate {
	return RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": 2}`, Description: "valid positive quantity"}
}

func validStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-1284"}}
}

func TestNewAPIFlowVector_Valid_Succeeds(t *testing.T) {
	benign := validBenign()
	v, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "Negative Quantity Schema Violation", SeverityHigh,
		"checkout API declares quantity as a positive integer", validMalicious(), &benign, "", validStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewAPIFlowVector: %v", err)
	}
	if v.ID != "APIFLOW-001" {
		t.Errorf("ID = %q, want %q", v.ID, "APIFLOW-001")
	}
}

func TestNewAPIFlowVector_EmptyID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewAPIFlowVector_VersionLessThanOne_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 0, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for version < 1, got nil")
	}
}

func TestNewAPIFlowVector_UnknownCategory_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, APIFlowCategory("bogus_category"), "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Category, got nil")
	}
}

func TestNewAPIFlowVector_UnknownSeverity_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", Severity("bogus_severity"), "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Severity, got nil")
	}
}

func TestNewAPIFlowVector_EmptyMaliciousMethod_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Method = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewAPIFlowVector_EmptyMaliciousPath_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Path = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Path, got nil")
	}
}

func TestNewAPIFlowVector_EmptyMaliciousDescription_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Description = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

// Review Focus: a malformed CWE ID must be rejected at construction, not
// silently stored and surfaced later in a client-facing report.
func TestNewAPIFlowVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{CWEIDs: []string{"not-a-cwe-id"}}, "x")
	if err == nil {
		t.Fatal("want error for malformed CWE ID, got nil")
	}
}

func TestNewAPIFlowVector_StandardsAllEmpty_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has no mapping field set, got nil")
	}
}

func TestNewAPIFlowVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

// Review Focus: both BenignCounterpart and NoBenignCounterpartReason set is
// a contradictory double-statement and must be rejected.
func TestNewAPIFlowVector_BothBenignAndReasonSet_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "no benign exists", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

// Review Focus: neither set is a silent omission and must be rejected.
func TestNewAPIFlowVector_NeitherBenignNorReasonSet_Rejected(t *testing.T) {
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), nil, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

func TestNewAPIFlowVector_BenignCounterpartInvalid_Rejected(t *testing.T) {
	benign := validBenign()
	benign.Description = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for an invalid BenignCounterpart (empty Description), got nil")
	}
}
