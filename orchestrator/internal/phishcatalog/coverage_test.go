package phishcatalog

import (
	"strings"
	"testing"
)

func TestNewCoverageReport_DuplicateScenarioID_Errors(t *testing.T) {
	entries := []ScenarioCoverage{
		{ScenarioID: "PH-X-001", Coverage: CoverageCatalogOnly},
		{ScenarioID: "PH-X-001", Coverage: CoverageAdapterTested},
	}
	if _, err := NewCoverageReport(entries); err == nil {
		t.Error("NewCoverageReport() with a duplicate scenario ID = nil error, want an error")
	}
}

func TestNewCoverageReport_InvalidCoverage_Errors(t *testing.T) {
	entries := []ScenarioCoverage{{ScenarioID: "PH-X-001", Coverage: CoverageState("bogus")}}
	if _, err := NewCoverageReport(entries); err == nil {
		t.Error("NewCoverageReport() with an unrecognized coverage state = nil error, want an error")
	}
}

func TestCoverageReport_CountsAlwaysSumToDenominator(t *testing.T) {
	entries := []ScenarioCoverage{
		{ScenarioID: "a", Coverage: CoverageCatalogOnly},
		{ScenarioID: "b", Coverage: CoverageFixtureTested},
		{ScenarioID: "c", Coverage: CoverageAdapterTested},
		{ScenarioID: "d", Coverage: CoverageLiveValidated},
	}
	r, err := NewCoverageReport(entries)
	if err != nil {
		t.Fatalf("NewCoverageReport() error = %v", err)
	}
	sum := r.CatalogOnlyCount() + r.FixtureTestedCount() + r.AdapterTestedCount() + r.LiveValidatedCount()
	if sum != r.Denominator() {
		t.Errorf("counts sum = %d, want Denominator() = %d", sum, r.Denominator())
	}
}

func TestCoverageReport_Summary_EmptyEntries_NoDivideByZeroPanic(t *testing.T) {
	r, err := NewCoverageReport(nil)
	if err != nil {
		t.Fatalf("NewCoverageReport(nil) error = %v", err)
	}
	if got := r.Summary(); !strings.Contains(got, "0/0") {
		t.Errorf("Summary() = %q, want it to name 0/0 scenarios", got)
	}
}

func TestCoverageReport_Summary_NeverCollapsesTiersIntoOneNumber(t *testing.T) {
	entries := []ScenarioCoverage{
		{ScenarioID: "a", Coverage: CoverageCatalogOnly},
		{ScenarioID: "b", Coverage: CoverageLiveValidated},
	}
	r, _ := NewCoverageReport(entries)
	got := r.Summary()
	for _, want := range []string{"catalog-only", "fixture-tested", "adapter-tested", "live-validated"} {
		if !strings.Contains(got, want) {
			t.Errorf("Summary() = %q, want it to name tier %q explicitly", got, want)
		}
	}
}

func TestCoverageReport_Entries_ReturnsACopyNotTheInternalSlice(t *testing.T) {
	entries := []ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageCatalogOnly}}
	r, _ := NewCoverageReport(entries)
	got := r.Entries()
	got[0].Coverage = CoverageLiveValidated
	if r.Entries()[0].Coverage != CoverageCatalogOnly {
		t.Error("mutating Entries()' returned slice mutated the report's own internal state")
	}
}

func TestAudspectPhishingCoverageReport_BuildsFromRealCatalog(t *testing.T) {
	r, err := AudspectPhishingCoverageReport()
	if err != nil {
		t.Fatalf("AudspectPhishingCoverageReport() error = %v", err)
	}
	scenarios, _ := AudspectPhishingCatalog()
	if r.Denominator() != len(scenarios) {
		t.Errorf("Denominator() = %d, want %d (one entry per real catalog scenario)", r.Denominator(), len(scenarios))
	}
}

func TestRequireNoCoverageRegression_NoChange_Succeeds(t *testing.T) {
	entries := []ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageAdapterTested}}
	r, _ := NewCoverageReport(entries)
	if err := RequireNoCoverageRegression(r, r); err != nil {
		t.Errorf("RequireNoCoverageRegression() with identical reports error = %v, want nil", err)
	}
}

func TestRequireNoCoverageRegression_Upgrade_Succeeds(t *testing.T) {
	baseline, _ := NewCoverageReport([]ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageFixtureTested}})
	current, _ := NewCoverageReport([]ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageLiveValidated}})
	if err := RequireNoCoverageRegression(baseline, current); err != nil {
		t.Errorf("RequireNoCoverageRegression() with a coverage upgrade error = %v, want nil", err)
	}
}

func TestRequireNoCoverageRegression_Downgrade_Errors(t *testing.T) {
	baseline, _ := NewCoverageReport([]ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageAdapterTested}})
	current, _ := NewCoverageReport([]ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageCatalogOnly}})
	err := RequireNoCoverageRegression(baseline, current)
	if err == nil || !strings.Contains(err.Error(), "a: regressed from adapter_tested to catalog_only") {
		t.Errorf("RequireNoCoverageRegression() error = %v, want it to name the regressed scenario", err)
	}
}

func TestRequireNoCoverageRegression_ScenarioRemoved_Errors(t *testing.T) {
	baseline, _ := NewCoverageReport([]ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageAdapterTested}})
	current, _ := NewCoverageReport(nil)
	err := RequireNoCoverageRegression(baseline, current)
	if err == nil || !strings.Contains(err.Error(), "removed from the catalog") {
		t.Errorf("RequireNoCoverageRegression() error = %v, want it to name the removed scenario", err)
	}
}

func TestRequireNoCoverageRegression_NewlyAddedScenario_NeverAPenalty(t *testing.T) {
	baseline, _ := NewCoverageReport([]ScenarioCoverage{{ScenarioID: "a", Coverage: CoverageAdapterTested}})
	current, _ := NewCoverageReport([]ScenarioCoverage{
		{ScenarioID: "a", Coverage: CoverageAdapterTested},
		{ScenarioID: "b", Coverage: CoverageCatalogOnly},
	})
	if err := RequireNoCoverageRegression(baseline, current); err != nil {
		t.Errorf("RequireNoCoverageRegression() with only a newly-added scenario error = %v, want nil", err)
	}
}

func TestAudspectPhishingCoverageReport_PassesItsOwnRegressionGateAgainstItself(t *testing.T) {
	r, err := AudspectPhishingCoverageReport()
	if err != nil {
		t.Fatalf("AudspectPhishingCoverageReport() error = %v", err)
	}
	if err := RequireNoCoverageRegression(r, r); err != nil {
		t.Errorf("RequireNoCoverageRegression() of the real catalog against itself error = %v, want nil", err)
	}
}
