package webgwefficacy

import (
	"strings"
	"testing"
)

func TestNewCoverageReport_DuplicateDomainID_Errors(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "first", Status: CoverageCovered},
		{DomainID: "01", DomainName: "duplicate", Status: CoverageCovered},
	})
	if err == nil {
		t.Fatal("NewCoverageReport: want error for duplicate DomainID, got nil")
	}
}

func TestNewCoverageReport_ExcludedWithoutReason_Errors(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "04", DomainName: "malware", Status: CoverageExcluded, ExclusionReason: ""},
	})
	if err == nil {
		t.Fatal("NewCoverageReport: want error for an Excluded domain with no documented reason, got nil")
	}
}

func TestNewCoverageReport_InvalidStatus_Errors(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "typo-status", Status: CoverageStatus("coverd")},
	})
	if err == nil {
		t.Fatal("NewCoverageReport: want error for a Status outside the three known values, got nil")
	}
}

func TestCoverageReport_CountsAlwaysSumToDenominator(t *testing.T) {
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "covered", Status: CoverageCovered},
		{DomainID: "02", DomainName: "excluded", Status: CoverageExcluded, ExclusionReason: "deferred"},
		{DomainID: "03", DomainName: "not-covered", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	sum := report.CoveredCount() + report.ExcludedCount() + report.NotCoveredCount()
	if sum != report.Denominator() {
		t.Errorf("CoveredCount()+ExcludedCount()+NotCoveredCount() = %d, want it to always equal Denominator() = %d -- a domain with an invalid Status must be rejected at construction, never silently uncounted", sum, report.Denominator())
	}
}

func TestNewCoverageReport_ValidMix_Succeeds(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "covered-domain", Status: CoverageCovered},
		{DomainID: "02", DomainName: "excluded-domain", Status: CoverageExcluded, ExclusionReason: "out of scope this round"},
		{DomainID: "03", DomainName: "not-covered-domain", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
}

func TestCoverageReport_Denominator_CountsNotCoveredDomainsToo(t *testing.T) {
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "covered", Status: CoverageCovered},
		{DomainID: "02", DomainName: "not-covered", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	if got := report.Denominator(); got != 2 {
		t.Errorf("Denominator() = %d, want 2 -- the not-covered domain must still count toward the total", got)
	}
	if got := report.CoveredCount(); got != 1 {
		t.Errorf("CoveredCount() = %d, want 1", got)
	}
	if got := report.NotCoveredCount(); got != 1 {
		t.Errorf("NotCoveredCount() = %d, want 1", got)
	}
}

func TestCoverageReport_Summary_IncludesExclusionReasons(t *testing.T) {
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "covered", Status: CoverageCovered},
		{DomainID: "04", DomainName: "malware", Status: CoverageExcluded, ExclusionReason: "EICAR-class testing not yet designed"},
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
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "covered", Status: CoverageCovered},
		{DomainID: "02", DomainName: "covered-2", Status: CoverageCovered},
		{DomainID: "03", DomainName: "not-covered", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	summary := report.Summary()
	if !strings.Contains(summary, "2/3") {
		t.Errorf("Summary() = %q, want it to contain the covered count alongside the denominator (\"2/3\"), never a bare percentage", summary)
	}
}

func TestCoverageReport_Summary_EmptyDomains_NoDivideByZeroPanic(t *testing.T) {
	report, err := NewCoverageReport(nil)
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	summary := report.Summary()
	if summary == "" {
		t.Error("Summary() = \"\", want a non-empty message even with zero domains defined")
	}
}
