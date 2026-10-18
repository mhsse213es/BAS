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

func TestPHBEC002_ExpectationLeavesUserInteractionNil(t *testing.T) {
	s := phBEC002()
	if s.Expectation.UserInteraction != nil {
		t.Error("PH-BEC-002.Expectation.UserInteraction is set, want nil (not applicable to this email-gateway+SOC narrative)")
	}
	if s.Expectation.Enforcement == nil || *s.Expectation.Enforcement != phishval.EnforcementBlocked {
		t.Error("PH-BEC-002.Expectation.Enforcement want *EnforcementBlocked")
	}
}
