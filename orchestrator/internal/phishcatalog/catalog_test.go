package phishcatalog

import (
	"testing"

	"github.com/audspect/bas/internal/phishval"
)

func TestAudspectPhishingCatalog_ContainsPHBEC002(t *testing.T) {
	catalog, err := AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog() error = %v", err)
	}
	s, ok := ByID(catalog, "PH-BEC-002")
	if !ok {
		t.Fatal("PH-BEC-002 not found in catalog")
	}
	if s.MappedImplementation == "" {
		t.Error("PH-BEC-002.MappedImplementation is empty, want a named implementation")
	}
	if s.Coverage != CoverageAdapterTested {
		t.Errorf("PH-BEC-002.Coverage = %q, want %q", s.Coverage, CoverageAdapterTested)
	}
}

func TestValidateCatalog_RejectsDuplicateID(t *testing.T) {
	dup := []Scenario{phBEC002(), phBEC002()}
	if err := ValidateCatalog(dup); err == nil {
		t.Error("ValidateCatalog() with duplicate ID = nil error, want an error")
	}
}

func TestValidateCatalog_RejectsCoverageClaimWithoutMappedImplementation(t *testing.T) {
	s := phBEC002()
	s.MappedImplementation = ""
	if err := ValidateCatalog([]Scenario{s}); err == nil {
		t.Error("ValidateCatalog() with Coverage set but no MappedImplementation = nil error, want an error")
	}
}

func TestValidateCatalog_AllowsCatalogOnlyWithoutMappedImplementation(t *testing.T) {
	s := Scenario{ID: "PH-TEST-999", Coverage: CoverageCatalogOnly}
	if err := ValidateCatalog([]Scenario{s}); err != nil {
		t.Errorf("ValidateCatalog() for an honest catalog-only stub = %v, want nil", err)
	}
}

func TestValidateCatalog_RejectsUnrecognizedCoverage(t *testing.T) {
	s := Scenario{ID: "PH-TEST-998", Coverage: "bogus"}
	if err := ValidateCatalog([]Scenario{s}); err == nil {
		t.Error("ValidateCatalog() with unrecognized coverage = nil error, want an error")
	}
}

func TestAudspectPhishingCatalog_PHBEC003And007AreVariantsOfPHBEC002(t *testing.T) {
	catalog, err := AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog() error = %v", err)
	}
	for _, id := range []string{"PH-BEC-003", "PH-BEC-007"} {
		v, ok := VariantByID(catalog, id)
		if !ok {
			t.Fatalf("%s not found as a variant", id)
		}
		if v.BaseScenarioID != "PH-BEC-002" {
			t.Errorf("%s.BaseScenarioID = %q, want %q", id, v.BaseScenarioID, "PH-BEC-002")
		}
		if v.Axis != VariantAxisNarrative {
			t.Errorf("%s.Axis = %q, want %q", id, v.Axis, VariantAxisNarrative)
		}
		// A variant ID must never also exist as its own standalone
		// Scenario -- that would be exactly the silent duplication
		// phishing.txt capability #3 forbids.
		if _, isAlsoScenario := ByID(catalog, id); isAlsoScenario {
			t.Errorf("%s exists as both a Variant and a standalone Scenario -- duplicated, not shared", id)
		}
	}
}

func TestValidateCatalog_RejectsVariantWithMismatchedBaseScenarioID(t *testing.T) {
	s := phBEC002()
	s.Variants = []Variant{{ID: "PH-BEC-999", BaseScenarioID: "PH-BEC-999-WRONG"}}
	if err := ValidateCatalog([]Scenario{s}); err == nil {
		t.Error("ValidateCatalog() with a variant's BaseScenarioID not matching its owning scenario = nil error, want an error")
	}
}

func TestPHBEC002_ExpectationLeavesUserInteractionNil(t *testing.T) {
	s := phBEC002()
	if s.Expectation.UserInteraction != nil {
		t.Error("PH-BEC-002.Expectation.UserInteraction is set, want nil (not applicable to this email-gateway+SOC narrative)")
	}
	if s.Expectation.Enforcement == nil || *s.Expectation.Enforcement != phishval.EnforcementBlocked {
		t.Error("PH-BEC-002.Expectation.Enforcement want *EnforcementBlocked")
	}
}
