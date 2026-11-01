package api

import (
	"math"
	"testing"
	"time"
)

func rowAt(agent, actor string, prevention float64, tested int, when time.Time) readinessRow {
	return readinessRow{AgentID: agent, Actor: actor, Prevention: prevention, Tested: tested, RecordedAt: when}
}

func near(a, b float64) bool { return math.Abs(a-b) < 0.05 }

var day0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// Only each agent's LATEST assessment counts toward the organisation figure.
func TestBuildOrgReadiness_UsesLatestAssessmentPerAgent(t *testing.T) {
	rows := []readinessRow{
		rowAt("A", "APT29", 0, 10, day0),                    // stale: superseded below
		rowAt("A", "APT29", 100, 10, day0.AddDate(0, 0, 1)), // latest for A
		rowAt("B", "APT29", 50, 10, day0),                   // latest for B
	}
	got := buildOrgReadiness(rows)
	if len(got) != 1 {
		t.Fatalf("actors = %d, want 1", len(got))
	}
	a := got[0]
	// latest A: 10/10 prevented; latest B: 5/10 prevented → 15/20 = 75%
	if !near(a.LatestPrevention, 75) {
		t.Fatalf("LatestPrevention = %v, want 75 (stale A row must not count)", a.LatestPrevention)
	}
	if a.AgentCount != 2 || a.TestedTechs != 20 || a.PreventedTechs != 15 {
		t.Fatalf("agents=%d tested=%d prevented=%d, want 2/20/15", a.AgentCount, a.TestedTechs, a.PreventedTechs)
	}
}

// Pooling technique counts is not averaging agent percentages.
func TestBuildOrgReadiness_PoolsTechniqueCountsNotPercentages(t *testing.T) {
	rows := []readinessRow{
		rowAt("A", "Lazarus", 100, 40, day0), // 40 of 40 prevented
		rowAt("B", "Lazarus", 0, 4, day0),    // 0 of 4 prevented
	}
	a := buildOrgReadiness(rows)[0]
	// pooled: 40/44 = 90.9%. An average of the two percentages would give 50%.
	if !near(a.LatestPrevention, 90.9) {
		t.Fatalf("LatestPrevention = %v, want 90.9 (pooled), not the 50 an average would give", a.LatestPrevention)
	}
}

// An actor with no tested techniques is omitted, never shown as 0%.
func TestBuildOrgReadiness_ZeroTestedIsOmitted(t *testing.T) {
	rows := []readinessRow{
		rowAt("A", "Untested", 0, 0, day0),
		rowAt("A", "Tested", 80, 5, day0),
	}
	got := buildOrgReadiness(rows)
	if len(got) != 1 || got[0].ActorName != "Tested" {
		t.Fatalf("got %+v, want only the tested actor", got)
	}
}

// Daily trend pools each day's assessments; delta is latest minus the first day.
func TestBuildOrgReadiness_TrendPoolsPerDay(t *testing.T) {
	rows := []readinessRow{
		rowAt("A", "FIN7", 40, 10, day0),                  // day 1: 4/10 = 40%
		rowAt("A", "FIN7", 80, 10, day0.AddDate(0, 0, 1)), // day 2: 8/10 = 80%
	}
	a := buildOrgReadiness(rows)[0]
	if len(a.History) != 2 || !near(a.History[0].Prevention, 40) || !near(a.History[1].Prevention, 80) {
		t.Fatalf("history = %+v", a.History)
	}
	if !near(a.PreventionDelta, 40) || a.Direction != "up" {
		t.Fatalf("delta=%v direction=%s, want 40/up", a.PreventionDelta, a.Direction)
	}
}

func TestBuildOrgReadiness_EmptyAndStable(t *testing.T) {
	if got := buildOrgReadiness(nil); len(got) != 0 {
		t.Fatalf("empty input = %+v", got)
	}
	got := buildOrgReadiness([]readinessRow{rowAt("A", "X", 60, 10, day0)})
	if got[0].Direction != "stable" || got[0].PreventionDelta != 0 {
		t.Fatalf("single day = %+v, want stable with zero delta", got[0])
	}
}
