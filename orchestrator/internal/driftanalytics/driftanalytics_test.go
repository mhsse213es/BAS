package driftanalytics

import (
	"testing"
	"time"
)

func day(n int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n)
}

func TestComputeDriftStats_EmptySequence(t *testing.T) {
	s := ComputeDriftStats(nil)
	if s.TotalRuns != 0 || s.CurrentStreakResult != "" || s.FirstVerifiedAt != nil || s.LastVerifiedAt != nil {
		t.Errorf("got %+v, want all-zero stats for an empty sequence", s)
	}
}

func TestComputeDriftStats_SingleRun(t *testing.T) {
	s := ComputeDriftStats([]VerificationOutcome{{Result: "pass", At: day(0)}})
	if s.TotalRuns != 1 || s.PassCount != 1 || s.DriftCount != 0 || s.LongestPassStreak != 1 || s.CurrentStreakResult != "pass" || s.CurrentStreakLength != 1 {
		t.Errorf("got %+v, want a single-pass no-drift result", s)
	}
}

func TestComputeDriftStats_AllFail_NeverDrifted(t *testing.T) {
	runs := []VerificationOutcome{
		{Result: "fail", At: day(0)}, {Result: "fail", At: day(1)},
		{Result: "fail", At: day(2)}, {Result: "fail", At: day(3)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 0 {
		t.Errorf("DriftCount = %d, want 0 (never fixed, so nothing to drift from)", s.DriftCount)
	}
	if s.LongestFailStreak != 4 || s.LongestPassStreak != 0 {
		t.Errorf("LongestFailStreak=%d LongestPassStreak=%d, want 4/0", s.LongestFailStreak, s.LongestPassStreak)
	}
}

func TestComputeDriftStats_AllPass_NeverDrifted(t *testing.T) {
	runs := []VerificationOutcome{
		{Result: "pass", At: day(0)}, {Result: "pass", At: day(1)},
		{Result: "pass", At: day(2)}, {Result: "pass", At: day(3)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 0 || s.LongestPassStreak != 4 || s.StabilityPercent != 100 {
		t.Errorf("got %+v, want DriftCount=0 LongestPassStreak=4 StabilityPercent=100", s)
	}
}

func TestComputeDriftStats_CanonicalExample_OneDrift(t *testing.T) {
	// FAIL, PASS, PASS, PASS, FAIL -- the spec's own worked example.
	runs := []VerificationOutcome{
		{Result: "fail", At: day(0)},
		{Result: "pass", At: day(1)},
		{Result: "pass", At: day(2)},
		{Result: "pass", At: day(3)},
		{Result: "fail", At: day(4)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 1 {
		t.Errorf("DriftCount = %d, want 1", s.DriftCount)
	}
	if s.LongestPassStreak != 3 || s.LongestFailStreak != 1 {
		t.Errorf("LongestPassStreak=%d LongestFailStreak=%d, want 3/1", s.LongestPassStreak, s.LongestFailStreak)
	}
	if s.CurrentStreakResult != "fail" || s.CurrentStreakLength != 1 {
		t.Errorf("CurrentStreakResult=%q CurrentStreakLength=%d, want fail/1", s.CurrentStreakResult, s.CurrentStreakLength)
	}
	if s.StabilityPercent != 60 {
		t.Errorf("StabilityPercent = %v, want 60", s.StabilityPercent)
	}
	if s.AverageDaysUntilDrift != 3 {
		t.Errorf("AverageDaysUntilDrift = %v, want 3 (day4 - day1)", s.AverageDaysUntilDrift)
	}
	if len(s.DriftEvents) != 1 || !s.DriftEvents[0].Equal(day(4)) {
		t.Errorf("DriftEvents = %v, want [day(4)]", s.DriftEvents)
	}
	if s.CurrentStreakStartedAt == nil || !s.CurrentStreakStartedAt.Equal(day(4)) {
		t.Errorf("CurrentStreakStartedAt = %v, want day(4)", s.CurrentStreakStartedAt)
	}
}

func TestComputeDriftStats_MultipleDrifts_AveragesCorrectly(t *testing.T) {
	// PASS(day0) -> FAIL(day5): drift 1, duration 5 days
	// PASS(day6) -> FAIL(day16): drift 2, duration 10 days
	// PASS(day17): current streak
	runs := []VerificationOutcome{
		{Result: "pass", At: day(0)},
		{Result: "fail", At: day(5)},
		{Result: "pass", At: day(6)},
		{Result: "fail", At: day(16)},
		{Result: "pass", At: day(17)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 2 {
		t.Fatalf("DriftCount = %d, want 2", s.DriftCount)
	}
	if s.AverageDaysUntilDrift != 7.5 {
		t.Errorf("AverageDaysUntilDrift = %v, want 7.5 ((5+10)/2)", s.AverageDaysUntilDrift)
	}
	if len(s.DriftEvents) != 2 || !s.DriftEvents[0].Equal(day(5)) || !s.DriftEvents[1].Equal(day(16)) {
		t.Errorf("DriftEvents = %v, want [day(5), day(16)]", s.DriftEvents)
	}
	if s.CurrentStreakResult != "pass" || s.CurrentStreakLength != 1 {
		t.Errorf("CurrentStreakResult=%q CurrentStreakLength=%d, want pass/1", s.CurrentStreakResult, s.CurrentStreakLength)
	}
}

func TestComputeDriftStats_FirstAndLastVerifiedAt(t *testing.T) {
	runs := []VerificationOutcome{{Result: "pass", At: day(0)}, {Result: "fail", At: day(10)}}
	s := ComputeDriftStats(runs)
	if s.FirstVerifiedAt == nil || !s.FirstVerifiedAt.Equal(day(0)) {
		t.Errorf("FirstVerifiedAt = %v, want day(0)", s.FirstVerifiedAt)
	}
	if s.LastVerifiedAt == nil || !s.LastVerifiedAt.Equal(day(10)) {
		t.Errorf("LastVerifiedAt = %v, want day(10)", s.LastVerifiedAt)
	}
}
