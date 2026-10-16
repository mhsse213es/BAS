package wafefficacy

import "testing"

func TestNewCoverageReport_DuplicateDomainID_Rejected(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageCovered},
		{DomainID: "01", DomainName: "B", Status: CoverageCovered},
	})
	if err == nil {
		t.Fatal("want error for duplicate DomainID, got nil")
	}
}

func TestNewCoverageReport_UnknownStatus_Rejected(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageStatus("bogus")},
	})
	if err == nil {
		t.Fatal("want error for unknown status, got nil")
	}
}

func TestNewCoverageReport_ExcludedWithoutReason_Rejected(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageExcluded},
	})
	if err == nil {
		t.Fatal("want error for excluded domain with empty ExclusionReason, got nil")
	}
}

func TestNewCoverageReport_ExcludedWithReason_Succeeds(t *testing.T) {
	if _, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageExcluded, ExclusionReason: "not built yet"},
	}); err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
}

func mustReport(t *testing.T) CoverageReport {
	t.Helper()
	r, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageCovered},
		{DomainID: "02", DomainName: "B", Status: CoverageExcluded, ExclusionReason: "reason"},
		{DomainID: "03", DomainName: "C", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	return r
}

func TestCoverageReport_CountsAndDenominator(t *testing.T) {
	r := mustReport(t)
	if r.Denominator() != 3 {
		t.Errorf("Denominator() = %d, want 3", r.Denominator())
	}
	if r.CoveredCount() != 1 {
		t.Errorf("CoveredCount() = %d, want 1", r.CoveredCount())
	}
	if r.ExcludedCount() != 1 {
		t.Errorf("ExcludedCount() = %d, want 1", r.ExcludedCount())
	}
	if r.NotCoveredCount() != 1 {
		t.Errorf("NotCoveredCount() = %d, want 1", r.NotCoveredCount())
	}
}

func TestCoverageReport_Exclusions_RendersReason(t *testing.T) {
	r := mustReport(t)
	excl := r.Exclusions()
	if len(excl) != 1 {
		t.Fatalf("len(Exclusions()) = %d, want 1", len(excl))
	}
	if !contains(excl[0], "reason") {
		t.Errorf("Exclusions()[0] = %q, want it to contain %q", excl[0], "reason")
	}
}

// Review Focus: the disclosure sentence must be in the real return
// value, not merely documented, and must appear regardless of domain
// contents (tested against two different reports).
func TestSummary_AlwaysIncludesNoLiveExecutionDisclosure(t *testing.T) {
	const disclosure = "evaluator-only"
	r1 := mustReport(t)
	if !contains(r1.Summary(), disclosure) {
		t.Errorf("Summary() = %q, want it to contain %q", r1.Summary(), disclosure)
	}

	r2, err := NewCoverageReport([]DomainCoverage{{DomainID: "99", DomainName: "Z", Status: CoverageCovered}})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	if !contains(r2.Summary(), disclosure) {
		t.Errorf("Summary() = %q, want it to contain %q", r2.Summary(), disclosure)
	}
}

func TestSummary_IncludesCoveredCountAndDenominator(t *testing.T) {
	r := mustReport(t)
	s := r.Summary()
	if !contains(s, "1/3") {
		t.Errorf("Summary() = %q, want it to contain %q", s, "1/3")
	}
}

func TestDomainsForDisplay_ReturnsAllDomainsInOrder(t *testing.T) {
	r := mustReport(t)
	got := r.DomainsForDisplay()
	if len(got) != 3 {
		t.Fatalf("len(DomainsForDisplay()) = %d, want 3", len(got))
	}
	if got[0].DomainID != "01" || got[1].DomainID != "02" || got[2].DomainID != "03" {
		t.Errorf("DomainsForDisplay() order = %v, want 01,02,03", []string{got[0].DomainID, got[1].DomainID, got[2].DomainID})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
