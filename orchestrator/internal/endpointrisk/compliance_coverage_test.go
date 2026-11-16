package endpointrisk

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/exposure"
)

func complianceCategory(t *testing.T, h EndpointHealth) CategoryScore {
	t.Helper()
	for _, c := range h.Categories {
		if c.ID == CategoryCompliance {
			return c
		}
	}
	t.Fatal("no compliance category")
	return CategoryScore{}
}

// A framework with too little tested is not scored, so a perfect resistance rate over a handful of controls cannot lift
// the health score. The category says why, and a real failed control still shows as a finding.
func TestCompliance_TooLittleTestedIsNotScoredAndSaysWhy(t *testing.T) {
	in := HealthInputs{Compliance: ComplianceInput{
		InsufficientCoverage: []string{"RBI", "PCI DSS"},
		FailedFindings:       []Finding{{Title: "Boundary defence", Severity: "High"}},
	}}
	h := ComputeHealth("a", exposure.AssetExposureProfile{}, in, HealthInputs{})
	c := complianceCategory(t, h)
	if c.Collected || c.Score != 0 {
		t.Fatalf("category = collected %v score %d, want not collected", c.Collected, c.Score)
	}
	if h.Measurable {
		t.Error("health was called measurable on the strength of an unscored compliance category")
	}
	for _, want := range []string{"RBI", "PCI DSS", "50%"} {
		if !strings.Contains(c.Note, want) {
			t.Errorf("note %q lacks %q", c.Note, want)
		}
	}
	if len(c.Findings) != 1 {
		t.Errorf("findings = %d, want the failed control kept even though the category is not scored", len(c.Findings))
	}
}

// Only the frameworks with enough coverage are averaged, and the note names the ones left out.
func TestCompliance_OnlyFrameworksWithEnoughCoverageAreAveraged(t *testing.T) {
	in := HealthInputs{Compliance: ComplianceInput{
		Collected:            true,
		PercentByFramework:   map[string]float64{"ISO": 80, "NIST": 60},
		InsufficientCoverage: []string{"RBI"},
	}}
	c := complianceCategory(t, ComputeHealth("a", exposure.AssetExposureProfile{}, in, HealthInputs{}))
	if !c.Collected || c.Score != 70 {
		t.Fatalf("category = collected %v score %d, want collected 70", c.Collected, c.Score)
	}
	if !strings.Contains(c.Note, "RBI") {
		t.Errorf("note %q does not say RBI was left out", c.Note)
	}
}

func TestCompliance_FullyCoveredHasNoNote(t *testing.T) {
	in := HealthInputs{Compliance: ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 90}}}
	if c := complianceCategory(t, ComputeHealth("a", exposure.AssetExposureProfile{}, in, HealthInputs{})); c.Note != "" {
		t.Errorf("note = %q, want none", c.Note)
	}
}
