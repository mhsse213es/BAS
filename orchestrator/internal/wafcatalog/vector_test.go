package wafcatalog

import "testing"

func validMalicious() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "' OR 1=1--", Description: "test payload"}
}

func validBenign() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "laptop stand", Description: "ordinary search term"}
}

func validStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-89"}, Top10Category: "A03:2021-Injection"}
}

func TestNewAttackVector_Valid_Succeeds(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "UNION-based SQLi", SeverityCritical,
		"target has a SQL-backed search endpoint", validMalicious(), &benign, "", validStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	if v.ID != "SQLI-001" {
		t.Errorf("ID = %q, want %q", v.ID, "SQLI-001")
	}
}

func TestNewAttackVector_EmptyID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewAttackVector_VersionBelowOne_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 0, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for Version < 1, got nil")
	}
}

// Review Focus: a Family value that is a syntactically valid string but not
// one of the 11 known constants must be rejected -- AttackFamily is just a
// string underneath, so Go's type system cannot catch a typo like this.
func TestNewAttackVector_UnknownFamily_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, AttackFamily("sql_injecton"), "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Family, got nil")
	}
}

func TestNewAttackVector_UnknownSeverity_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", Severity("extreme"), "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Severity, got nil")
	}
}

func TestNewAttackVector_MaliciousMissingMethod_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Method = ""
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewAttackVector_MaliciousMissingDescription_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Description = ""
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

// Review Focus: a CWE ID with the wrong case or missing the "CWE-" prefix
// must be rejected by the format check.
func TestNewAttackVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := validBenign()
	for _, bad := range []string{"cwe-89", "89", "CWE89", "CWE-"} {
		standards := StandardsMapping{CWEIDs: []string{bad}}
		_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", standards, "x")
		if err == nil {
			t.Errorf("CWE ID %q: want error, got nil", bad)
		}
	}
}

func TestNewAttackVector_NoStandardsMapping_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has none of CWEIDs/WSTGCategory/Top10Category/APITop10Category set, got nil")
	}
}

func TestNewAttackVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestNewAttackVector_NeitherBenignNorReason_Rejected(t *testing.T) {
	_, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "x", SeverityCritical, "x", validMalicious(), nil, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

// Review Focus: setting BOTH BenignCounterpart and a non-empty
// NoBenignCounterpartReason is a contradictory state and must be rejected,
// never resolved by silently picking one.
func TestNewAttackVector_BothBenignAndReason_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "x", SeverityCritical, "x", validMalicious(), &benign, "no counterpart needed", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

func TestNewAttackVector_NoBenignCounterpartReason_Succeeds(t *testing.T) {
	v, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "metadata SSRF", SeverityCritical, "x",
		validMalicious(), nil, "no legitimate client request targets this address range", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	if v.BenignCounterpart != nil {
		t.Error("BenignCounterpart should be nil")
	}
}
