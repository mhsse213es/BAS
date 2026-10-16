package emailgwefficacy

import (
	"strings"
	"testing"
)

func TestNewCoverageReport_DuplicateAreaID_Errors(t *testing.T) {
	_, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "first", Status: CoverageCovered},
		{AreaID: "A", AreaName: "duplicate", Status: CoverageCovered},
	})
	if err == nil {
		t.Fatal("NewCoverageReport: want error for duplicate AreaID, got nil")
	}
}

func TestNewCoverageReport_ExcludedWithoutReason_Errors(t *testing.T) {
	_, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "C", AreaName: "attachments", Status: CoverageExcluded, ExclusionReason: ""},
	})
	if err == nil {
		t.Fatal("NewCoverageReport: want error for an Excluded area with no documented reason, got nil")
	}
}

func TestNewCoverageReport_InvalidStatus_Errors(t *testing.T) {
	_, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "typo-status", Status: CoverageStatus("coverd")},
	})
	if err == nil {
		t.Fatal("NewCoverageReport: want error for a Status outside the three known values, got nil")
	}
}

func TestCoverageReport_CountsAlwaysSumToDenominator(t *testing.T) {
	report, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "covered", Status: CoverageCovered},
		{AreaID: "B", AreaName: "excluded", Status: CoverageExcluded, ExclusionReason: "deferred"},
		{AreaID: "C", AreaName: "not-covered", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	sum := report.CoveredCount() + report.ExcludedCount() + report.NotCoveredCount()
	if sum != report.Denominator() {
		t.Errorf("CoveredCount()+ExcludedCount()+NotCoveredCount() = %d, want it to always equal Denominator() = %d -- an area with an invalid Status must be rejected at construction, never silently uncounted", sum, report.Denominator())
	}
}

func TestNewCoverageReport_ValidMix_Succeeds(t *testing.T) {
	_, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "covered-area", Status: CoverageCovered},
		{AreaID: "B", AreaName: "excluded-area", Status: CoverageExcluded, ExclusionReason: "out of scope this round"},
		{AreaID: "C", AreaName: "not-covered-area", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
}

func TestCoverageReport_Denominator_CountsNotCoveredAreasToo(t *testing.T) {
	report, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "covered", Status: CoverageCovered},
		{AreaID: "B", AreaName: "not-covered", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	if got := report.Denominator(); got != 2 {
		t.Errorf("Denominator() = %d, want 2 -- the not-covered area must still count toward the total", got)
	}
	if got := report.CoveredCount(); got != 1 {
		t.Errorf("CoveredCount() = %d, want 1", got)
	}
	if got := report.NotCoveredCount(); got != 1 {
		t.Errorf("NotCoveredCount() = %d, want 1", got)
	}
}

func TestCoverageReport_Summary_IncludesExclusionReasons(t *testing.T) {
	report, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "covered", Status: CoverageCovered},
		{AreaID: "C", AreaName: "attachments", Status: CoverageExcluded, ExclusionReason: "EICAR-class testing not yet designed"},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	summary := report.Summary()
	if !strings.Contains(summary, "EICAR-class testing not yet designed") {
		t.Errorf("Summary() = %q, want it to contain the exclusion's documented reason, not just a count", summary)
	}
}

func TestCoverageReport_Summary_IncludesDenominatorAlongsidePercentage(t *testing.T) {
	report, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "covered", Status: CoverageCovered},
		{AreaID: "B", AreaName: "covered-2", Status: CoverageCovered},
		{AreaID: "C", AreaName: "not-covered", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	summary := report.Summary()
	if !strings.Contains(summary, "2/3") {
		t.Errorf("Summary() = %q, want it to contain the covered count alongside the denominator (\"2/3\"), never a bare percentage", summary)
	}
}

func TestCoverageReport_Summary_EmptyAreas_NoDivideByZeroPanic(t *testing.T) {
	report, err := NewCoverageReport(nil)
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	summary := report.Summary()
	if summary == "" {
		t.Error("Summary() = \"\", want a non-empty message even with zero areas defined")
	}
}

func TestCoverageReport_Areas_ReturnsACopyNotTheInternalSlice(t *testing.T) {
	report, err := NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "covered", Status: CoverageCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	areas := report.Areas()
	if len(areas) != 1 || areas[0].AreaID != "A" {
		t.Fatalf("Areas() = %+v, want exactly the one area this report was built from", areas)
	}
	areas[0].AreaID = "mutated"
	if got := report.Areas()[0].AreaID; got != "A" {
		t.Errorf("after mutating the returned slice, Areas()[0].AreaID = %q, want %q -- Areas() must return a copy, never the internal slice itself", got, "A")
	}
}

// TestAudspectEmailGWCoverageReport_MatchesArchitectureSpecAreaCount
// guards against this function silently drifting from §5's own
// Coverage Matrix table -- emailGW.txt's taxonomy has exactly 7 areas
// (A-G), and this report must account for every one of them, never
// silently drop or duplicate an area.
func TestAudspectEmailGWCoverageReport_MatchesArchitectureSpecAreaCount(t *testing.T) {
	report, err := AudspectEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectEmailGWCoverageReport: %v", err)
	}
	if got := report.Denominator(); got != 7 {
		t.Errorf("Denominator() = %d, want 7 -- emailGW.txt names exactly 7 taxonomy areas (A-G)", got)
	}
}
