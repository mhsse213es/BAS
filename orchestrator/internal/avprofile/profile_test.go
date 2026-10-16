package avprofile

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
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
	p, err := NewProfile("AVPROFILE-BFSI", "Banking, Financial Services and Insurance", ProfileIndustry,
		[]string{"AV-FILE-001", "AV-CREDACCESS-001"}, []ComplianceReference{mustComplianceRef(t)}, "rationale text", "provenance text")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if p.ID != "AVPROFILE-BFSI" {
		t.Errorf("ID = %q, want %q", p.ID, "AVPROFILE-BFSI")
	}
}

func TestNewProfile_EmptyID_Rejected(t *testing.T) {
	_, err := NewProfile("", "x", ProfileIndustry, []string{"AV-FILE-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewProfile_EmptyName_Rejected(t *testing.T) {
	_, err := NewProfile("AVPROFILE-BFSI", "", ProfileIndustry, []string{"AV-FILE-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty name, got nil")
	}
}

func TestNewProfile_InvalidKind_Rejected(t *testing.T) {
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileKind("bogus_kind"), []string{"AV-FILE-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for an unknown ProfileKind, got nil")
	}
}

func TestNewProfile_EmptyVectorIDs_Rejected(t *testing.T) {
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, []string{}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty vectorIDs, got nil")
	}
}

// Review Focus: a duplicate ID must be detected, not just an empty slice.
func TestNewProfile_DuplicateVectorID_Rejected(t *testing.T) {
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, []string{"AV-FILE-001", "AV-FILE-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for a duplicate vectorIDs entry, got nil")
	}
}

func TestNewProfile_EmptyComplianceReferences_Rejected(t *testing.T) {
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, []string{"AV-FILE-001"}, []ComplianceReference{}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty complianceReferences, got nil")
	}
}

// Review Focus: a struct-literal ComplianceReference with an empty
// Framework must be caught, not just an empty slice -- the validation
// must inspect field values, not just len().
func TestNewProfile_ComplianceReferenceWithEmptyFramework_Rejected(t *testing.T) {
	bad := ComplianceReference{Framework: "", VerificationStatus: Unverified, Note: "y"}
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, []string{"AV-FILE-001"}, []ComplianceReference{bad}, "r", "p")
	if err == nil {
		t.Fatal("want error for a complianceReferences entry with an empty Framework, got nil")
	}
}

func TestNewProfile_ComplianceReferenceWithEmptyNote_Rejected(t *testing.T) {
	bad := ComplianceReference{Framework: "x", VerificationStatus: Unverified, Note: ""}
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, []string{"AV-FILE-001"}, []ComplianceReference{bad}, "r", "p")
	if err == nil {
		t.Fatal("want error for a complianceReferences entry with an empty Note, got nil")
	}
}

func TestNewProfile_EmptyRationale_Rejected(t *testing.T) {
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, []string{"AV-FILE-001"}, []ComplianceReference{mustComplianceRef(t)}, "", "p")
	if err == nil {
		t.Fatal("want error for empty rationale, got nil")
	}
}

func TestNewProfile_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, []string{"AV-FILE-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func mustProfile(t *testing.T, ids []string) Profile {
	t.Helper()
	p, err := NewProfile("AVPROFILE-BFSI", "x", ProfileIndustry, ids, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	return p
}

func TestValidateAgainstCatalog_AllPresent_ReturnsNil(t *testing.T) {
	profile := mustProfile(t, []string{"AV-FILE-001", "AV-NET-001"})
	catalog := []avcatalog.Vector{{ID: "AV-FILE-001"}, {ID: "AV-NET-001"}, {ID: "AV-SCRIPT-001"}}
	if err := ValidateAgainstCatalog(profile, catalog); err != nil {
		t.Fatalf("ValidateAgainstCatalog: %v", err)
	}
}

// Review Focus: the error must name the specific missing ID.
func TestValidateAgainstCatalog_MissingID_ReturnsErrorNamingIt(t *testing.T) {
	profile := mustProfile(t, []string{"AV-FILE-001", "NOTAREALID-999"})
	catalog := []avcatalog.Vector{{ID: "AV-FILE-001"}}
	err := ValidateAgainstCatalog(profile, catalog)
	if err == nil {
		t.Fatal("want error for a missing vector ID, got nil")
	}
	if !strings.Contains(err.Error(), "NOTAREALID-999") {
		t.Errorf("error = %q, want it to name the missing ID %q", err.Error(), "NOTAREALID-999")
	}
}

func TestWithControlObjectives_Valid_Succeeds(t *testing.T) {
	base := mustProfile(t, []string{"AV-CONFIG-002"})
	covered, err := NewControlObjectiveCoverage("restricted or disconnected networks", "AV-CONFIG-002", "rationale", "evidence", CoverageStatusCovered)
	if err != nil {
		t.Fatalf("NewControlObjectiveCoverage: %v", err)
	}
	p, err := WithControlObjectives(base, []ControlObjectiveCoverage{covered})
	if err != nil {
		t.Fatalf("WithControlObjectives: %v", err)
	}
	if len(p.ControlObjectives) != 1 {
		t.Fatalf("ControlObjectives len = %d, want 1", len(p.ControlObjectives))
	}
}

func TestWithControlObjectives_Empty_Rejected(t *testing.T) {
	base := mustProfile(t, []string{"AV-CONFIG-002"})
	if _, err := WithControlObjectives(base, nil); err == nil {
		t.Fatal("want error for empty objectives, got nil")
	}
}

func TestWithControlObjectives_DuplicateObjective_Rejected(t *testing.T) {
	base := mustProfile(t, []string{"AV-CONFIG-002"})
	o1, err := NewControlObjectiveCoverage("same objective", "AV-CONFIG-002", "r", "e", CoverageStatusCovered)
	if err != nil {
		t.Fatalf("NewControlObjectiveCoverage: %v", err)
	}
	o2, err := NewControlObjectiveCoverage("same objective", "", "a different gap reason", "", CoverageStatusGap)
	if err != nil {
		t.Fatalf("NewControlObjectiveCoverage: %v", err)
	}
	if _, err := WithControlObjectives(base, []ControlObjectiveCoverage{o1, o2}); err == nil {
		t.Fatal("want error for a duplicate objective name, got nil")
	}
}

// Review Focus: ValidateAgainstCatalog must also catch a stale VectorID
// inside ControlObjectives, not just the flat VectorIDs list.
func TestValidateAgainstCatalog_StaleControlObjectiveVectorID_ReturnsErrorNamingIt(t *testing.T) {
	base := mustProfile(t, []string{"AV-FILE-001"})
	covered, err := NewControlObjectiveCoverage("some objective", "NOTAREALID-999", "r", "e", CoverageStatusCovered)
	if err != nil {
		t.Fatalf("NewControlObjectiveCoverage: %v", err)
	}
	profile, err := WithControlObjectives(base, []ControlObjectiveCoverage{covered})
	if err != nil {
		t.Fatalf("WithControlObjectives: %v", err)
	}
	catalog := []avcatalog.Vector{{ID: "AV-FILE-001"}}
	err = ValidateAgainstCatalog(profile, catalog)
	if err == nil {
		t.Fatal("want error for a stale ControlObjectives vector ID, got nil")
	}
	if !strings.Contains(err.Error(), "NOTAREALID-999") {
		t.Errorf("error = %q, want it to name the stale ID %q", err.Error(), "NOTAREALID-999")
	}
}
