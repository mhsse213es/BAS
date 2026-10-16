package wafprofile

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func mustComplianceRef(t *testing.T) ComplianceReference {
	t.Helper()
	c, err := NewComplianceReference("x", Unverified, "y", "")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	return c
}

func TestNewProfile_Valid_Succeeds(t *testing.T) {
	p, err := NewProfile("WAFPROFILE-BFSI", "Banking, Financial Services and Insurance", ProfileIndustry,
		[]string{"SQLI-001", "AUTH-001"}, []ComplianceReference{mustComplianceRef(t)}, "rationale text", "provenance text")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if p.ID != "WAFPROFILE-BFSI" {
		t.Errorf("ID = %q, want %q", p.ID, "WAFPROFILE-BFSI")
	}
}

func TestNewProfile_EmptyID_Rejected(t *testing.T) {
	_, err := NewProfile("", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewProfile_EmptyName_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty name, got nil")
	}
}

func TestNewProfile_InvalidKind_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileKind("bogus_kind"), []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for an unknown ProfileKind, got nil")
	}
}

func TestNewProfile_EmptyAttackVectorIDs_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty attackVectorIDs, got nil")
	}
}

// Review Focus: a duplicate ID must be detected, not just an empty slice.
func TestNewProfile_DuplicateAttackVectorID_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001", "SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for a duplicate attackVectorIDs entry, got nil")
	}
}

func TestNewProfile_EmptyComplianceReferences_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty complianceReferences, got nil")
	}
}

// Review Focus: a struct-literal ComplianceReference with an empty
// Framework must be caught, not just an empty slice -- the validation
// must inspect field values, not just len().
func TestNewProfile_ComplianceReferenceWithEmptyFramework_Rejected(t *testing.T) {
	bad := ComplianceReference{Framework: "", VerificationStatus: Unverified, Note: "y"}
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{bad}, "r", "p")
	if err == nil {
		t.Fatal("want error for a complianceReferences entry with an empty Framework, got nil")
	}
}

func TestNewProfile_ComplianceReferenceWithEmptyNote_Rejected(t *testing.T) {
	bad := ComplianceReference{Framework: "x", VerificationStatus: Unverified, Note: ""}
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{bad}, "r", "p")
	if err == nil {
		t.Fatal("want error for a complianceReferences entry with an empty Note, got nil")
	}
}

func TestNewProfile_EmptyRationale_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "", "p")
	if err == nil {
		t.Fatal("want error for empty rationale, got nil")
	}
}

func TestNewProfile_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func mustProfile(t *testing.T, ids []string) Profile {
	t.Helper()
	p, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, ids, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	return p
}

func TestValidateAgainstCatalog_AllPresent_ReturnsNil(t *testing.T) {
	profile := mustProfile(t, []string{"SQLI-001", "XSS-001"})
	catalog := []wafcatalog.AttackVector{{ID: "SQLI-001"}, {ID: "XSS-001"}, {ID: "AUTH-001"}}
	if err := ValidateAgainstCatalog(profile, catalog); err != nil {
		t.Fatalf("ValidateAgainstCatalog: %v", err)
	}
}

// Review Focus: the error must name the specific missing ID.
func TestValidateAgainstCatalog_MissingID_ReturnsErrorNamingIt(t *testing.T) {
	profile := mustProfile(t, []string{"SQLI-001", "NOTAREALID-999"})
	catalog := []wafcatalog.AttackVector{{ID: "SQLI-001"}}
	err := ValidateAgainstCatalog(profile, catalog)
	if err == nil {
		t.Fatal("want error for a missing attack-vector ID, got nil")
	}
	if !strings.Contains(err.Error(), "NOTAREALID-999") {
		t.Errorf("error = %q, want it to name the missing ID %q", err.Error(), "NOTAREALID-999")
	}
}
