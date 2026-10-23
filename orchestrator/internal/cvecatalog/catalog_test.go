package cvecatalog

import "testing"

func TestAudspectCVEAssessmentCatalog_ReturnsValidatedCatalog(t *testing.T) {
	entries, err := AudspectCVEAssessmentCatalog()
	if err != nil {
		t.Fatalf("AudspectCVEAssessmentCatalog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if err := ValidateCatalog(entries); err != nil {
		t.Errorf("returned catalog fails ValidateCatalog: %v", err)
	}
}

func TestAudspectCVEAssessmentCatalog_IncludesLog4Shell(t *testing.T) {
	entries, err := AudspectCVEAssessmentCatalog()
	if err != nil {
		t.Fatalf("AudspectCVEAssessmentCatalog: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ID == "CVE-2021-44228" {
			found = true
		}
	}
	if !found {
		t.Fatal("CVE-2021-44228 (Log4Shell) is not in the catalog")
	}
}

func TestLookup_FindsKnownCVE(t *testing.T) {
	e, ok, err := Lookup("CVE-2021-44228")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("Lookup(CVE-2021-44228) ok = false, want true")
	}
	if e.ID != "CVE-2021-44228" {
		t.Fatalf("Lookup returned entry with ID %q", e.ID)
	}
}

func TestLookup_UnknownCVEReportsAbsentNotError(t *testing.T) {
	_, ok, err := Lookup("CVE-9999-00000")
	if err != nil {
		t.Fatalf("Lookup of an unknown CVE should not itself error: %v", err)
	}
	if ok {
		t.Fatal("Lookup(CVE-9999-00000) ok = true, want false -- this CVE is not cataloged")
	}
}

func TestValidateCatalog_RejectsDuplicateID(t *testing.T) {
	e, err := log4ShellEntry()
	if err != nil {
		t.Fatalf("log4ShellEntry: %v", err)
	}
	if err := ValidateCatalog([]CVEEntry{e, e}); err == nil {
		t.Fatal("ValidateCatalog must reject two entries sharing the same CVE ID")
	}
}
