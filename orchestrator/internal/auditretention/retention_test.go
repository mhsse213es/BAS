package auditretention

import (
	"testing"
	"time"
)

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func TestCoverage_MeetsMinimumAtExactlyTheFloor(t *testing.T) {
	oldest := now.AddDate(0, 0, -MinimumRetentionDays)
	s := Coverage(&oldest, now)
	if !s.MeetsMinimum {
		t.Fatalf("oldest entry exactly %d days old must meet the minimum", MinimumRetentionDays)
	}
}

func TestCoverage_ShortOfMinimumOneDayEarly(t *testing.T) {
	oldest := now.AddDate(0, 0, -MinimumRetentionDays+1)
	s := Coverage(&oldest, now)
	if s.MeetsMinimum {
		t.Fatal("179 days of history must not meet the 180-day minimum")
	}
}

func TestCoverage_NoEntriesDoesNotMeetMinimum(t *testing.T) {
	s := Coverage(nil, now)
	if s.MeetsMinimum || s.OldestEntry != nil {
		t.Fatalf("an empty audit log cannot show retention: %+v", s)
	}
	if s.MinimumDays != 180 {
		t.Fatalf("minimum %d, want 180", s.MinimumDays)
	}
}

func TestCoverage_ReportsAgeInWholeDays(t *testing.T) {
	oldest := now.AddDate(0, 0, -200).Add(-3 * time.Hour)
	s := Coverage(&oldest, now)
	if s.AgeDays != 200 {
		t.Fatalf("age %d days, want 200", s.AgeDays)
	}
}
