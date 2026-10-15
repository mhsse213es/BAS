package webgwefficacy

import (
	"strings"
	"testing"
	"time"
)

// TestCoverageReport_Summary_RealWebGWDomainCoverage_NineOfTwelve uses
// this initiative's own real, current domain-coverage count as of
// Phase 4 -- not an invented example. Per the architecture spec's §5
// Coverage Matrix: domains 01, 02, 03, 05, 06, 08, 09, 10, 11 are
// covered (9); domains 04 and 07 remain unbuilt, and domain 12 is
// marked "Started" (not fully covered), so the honest count is 9 of
// 12, with zero of the 12 domains individually excluded from this
// count.
func TestCoverageReport_Summary_RealWebGWDomainCoverage_NineOfTwelve(t *testing.T) {
	report := NewCoverageReport(12, 9, nil, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	summary := report.Summary()

	if !strings.Contains(summary, "9") || !strings.Contains(summary, "12") {
		t.Errorf("Summary() = %q, want it to state both covered (9) and total (12)", summary)
	}
	if !strings.Contains(summary, "exclusions: none") {
		t.Errorf("Summary() = %q, want it to explicitly state there are no exclusions, never omit the clause", summary)
	}
}

// TestCoverageReport_Summary_WithExclusions_CitesEachReason uses the
// real Zscaler-Unsupported exclusion from Phase 4
// (docs/webgw-mastery-qa-log.md item #3) as a genuine exclusion
// example -- proving CoverageExclusion generalizes beyond "domain"
// to any denominator item this package reports coverage over.
func TestCoverageReport_Summary_WithExclusions_CitesEachReason(t *testing.T) {
	exclusions := []CoverageExclusion{
		{ItemID: "zscaler", Reason: "no self-serve trial/signup; sales-gated"},
	}
	report := NewCoverageReport(6, 1, exclusions, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	summary := report.Summary()

	if !strings.Contains(summary, "zscaler") {
		t.Errorf("Summary() = %q, want it to name the excluded item", summary)
	}
	if !strings.Contains(summary, "sales-gated") {
		t.Errorf("Summary() = %q, want it to cite the exclusion's own reason", summary)
	}
}

// TestCoverageReport_Summary_ZeroTotalItems_NoPanic guards the
// percentage calculation's division against a zero denominator.
func TestCoverageReport_Summary_ZeroTotalItems_NoPanic(t *testing.T) {
	report := NewCoverageReport(0, 0, nil, time.Now())

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Summary() panicked on zero TotalItems: %v", r)
		}
	}()
	_ = report.Summary()
}

// TestCoverageReport_Summary_NeverBarePercentage confirms the
// rendered string is never JUST a percentage -- it must always carry
// the raw covered/total counts alongside any percentage figure.
func TestCoverageReport_Summary_NeverBarePercentage(t *testing.T) {
	report := NewCoverageReport(4, 2, nil, time.Now())
	summary := report.Summary()

	if !strings.Contains(summary, "2") || !strings.Contains(summary, "4") {
		t.Errorf("Summary() = %q, want the raw covered/total counts present alongside any percentage", summary)
	}
}
