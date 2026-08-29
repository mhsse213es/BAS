package slareport

import (
	"testing"
	"time"
)

func TestComputeReport_EmptyInput(t *testing.T) {
	r := ComputeReport(nil)
	if r.Overall.TotalEpisodes != 0 || r.Overall.ComplianceRate != 0 {
		t.Fatalf("Overall = %+v, want zero-valued (no divide-by-zero)", r.Overall)
	}
	if len(r.BySeverity) != 0 || len(r.MonthlyTrend) != 0 {
		t.Fatalf("BySeverity=%v MonthlyTrend=%v, want both empty", r.BySeverity, r.MonthlyTrend)
	}
}

func TestComputeReport_AllOnTime_100PercentCompliance(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	before := deadline.Add(-time.Hour)
	episodes := []Episode{
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
	}
	r := ComputeReport(episodes)
	if r.Overall.OnTime != 2 || r.Overall.Late != 0 || r.Overall.ComplianceRate != 100 {
		t.Fatalf("Overall = %+v, want OnTime=2 Late=0 ComplianceRate=100", r.Overall)
	}
}

func TestComputeReport_AllLate_0PercentCompliance(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	after := deadline.Add(time.Hour)
	episodes := []Episode{
		{Severity: "Critical", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &after},
	}
	r := ComputeReport(episodes)
	if r.Overall.OnTime != 0 || r.Overall.Late != 1 || r.Overall.ComplianceRate != 0 {
		t.Fatalf("Overall = %+v, want OnTime=0 Late=1 ComplianceRate=0", r.Overall)
	}
}

func TestComputeReport_ResolvedExactlyAtDeadline_CountsAsLate(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	episodes := []Episode{
		{Severity: "Medium", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &deadline},
	}
	r := ComputeReport(episodes)
	if r.Overall.Late != 1 {
		t.Fatalf("Overall = %+v, want Late=1 (deadline exactly reached counts as breached, matching EvaluateSLABreach)", r.Overall)
	}
}

func TestComputeReport_CurrentlyOpenExcludedFromComplianceRate(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	before := deadline.Add(-time.Hour)
	episodes := []Episode{
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before}, // on time
		{Severity: "High", DeadlineAt: deadline, Status: "active"},                        // still open
		{Severity: "High", DeadlineAt: deadline, Status: "breached"},                      // still open, already missed
	}
	r := ComputeReport(episodes)
	if r.Overall.TotalEpisodes != 3 {
		t.Errorf("TotalEpisodes = %d, want 3", r.Overall.TotalEpisodes)
	}
	if r.Overall.CurrentlyOpen != 2 {
		t.Errorf("CurrentlyOpen = %d, want 2 (active + breached)", r.Overall.CurrentlyOpen)
	}
	if r.Overall.OnTime != 1 || r.Overall.Late != 0 || r.Overall.ComplianceRate != 100 {
		t.Errorf("OnTime=%d Late=%d ComplianceRate=%.1f, want 1/0/100 (open episodes excluded from the rate)",
			r.Overall.OnTime, r.Overall.Late, r.Overall.ComplianceRate)
	}
}

func TestComputeReport_BySeverity_OnlyIncludesSeveritiesWithEpisodes(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	before := deadline.Add(-time.Hour)
	after := deadline.Add(time.Hour)
	episodes := []Episode{
		{Severity: "Critical", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &after},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
	}
	r := ComputeReport(episodes)
	if len(r.BySeverity) != 2 {
		t.Fatalf("BySeverity = %+v, want exactly 2 rows (Critical, High -- Medium/Low have no episodes)", r.BySeverity)
	}
	bySev := map[string]Stats{}
	for _, s := range r.BySeverity {
		bySev[s.Severity] = s
	}
	if bySev["Critical"].TotalEpisodes != 1 || bySev["Critical"].ComplianceRate != 100 {
		t.Errorf("Critical = %+v, want TotalEpisodes=1 ComplianceRate=100", bySev["Critical"])
	}
	if bySev["High"].TotalEpisodes != 2 || bySev["High"].OnTime != 1 || bySev["High"].Late != 1 || bySev["High"].ComplianceRate != 50 {
		t.Errorf("High = %+v, want TotalEpisodes=2 OnTime=1 Late=1 ComplianceRate=50", bySev["High"])
	}
}

func TestComputeReport_MonthlyTrend_BucketsByResolvedMonth(t *testing.T) {
	deadline := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	julOnTime := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	julLate := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	augOnTime := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	augDeadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	episodes := []Episode{
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &julOnTime},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &julLate},
		{Severity: "High", DeadlineAt: augDeadline, Status: "resolved", ResolvedAt: &augOnTime},
		{Severity: "High", DeadlineAt: augDeadline, Status: "active"}, // still open -- never bucketed into a month
	}
	r := ComputeReport(episodes)
	if len(r.MonthlyTrend) != 2 {
		t.Fatalf("MonthlyTrend = %+v, want exactly 2 months", r.MonthlyTrend)
	}
	byMonth := map[string]MonthStats{}
	for _, m := range r.MonthlyTrend {
		byMonth[m.Month] = m
	}
	if byMonth["2026-07"].Resolved != 2 || byMonth["2026-07"].OnTime != 1 || byMonth["2026-07"].ComplianceRate != 50 {
		t.Errorf("2026-07 = %+v, want Resolved=2 OnTime=1 ComplianceRate=50", byMonth["2026-07"])
	}
	if byMonth["2026-08"].Resolved != 1 || byMonth["2026-08"].OnTime != 1 || byMonth["2026-08"].ComplianceRate != 100 {
		t.Errorf("2026-08 = %+v, want Resolved=1 OnTime=1 ComplianceRate=100", byMonth["2026-08"])
	}
}
