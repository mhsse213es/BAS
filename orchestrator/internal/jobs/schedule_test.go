package jobs

import (
	"testing"
	"time"
)

func TestIsTerminalJobState(t *testing.T) {
	cases := map[string]bool{
		JobStateRequested: false,
		JobStateRunning:   false,
		JobStateCompleted: true,
		JobStatePartial:   true,
		JobStateFailed:    true,
		JobStateCancelled: true,
	}
	for state, want := range cases {
		if got := IsTerminalJobState(state); got != want {
			t.Errorf("IsTerminalJobState(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestNextOccurrenceSince_FirstOccurrenceEverChecked(t *testing.T) {
	// A Friday 23:00 UTC schedule, never checked before (LastOccurrenceAt
	// nil), evaluated on the following Monday -- should find last Friday's
	// occurrence.
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC"} // 5 = Friday
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)              // a Monday
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true (first-ever check should find last Friday)")
	}
	want := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC) // the preceding Friday
	if !occurrence.Equal(want) {
		t.Errorf("occurrence = %v, want %v", occurrence, want)
	}
}

func TestNextOccurrenceSince_AlreadyHandled_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC"}
	already := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC)
	sch.LastOccurrenceAt = &already
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) // still the same week, no new Friday yet
	_, ok := nextOccurrenceSince(sch, now)
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- this occurrence was already handled")
	}
}

func TestNextOccurrenceSince_TimeOfDayNotYetReachedToday(t *testing.T) {
	sch := Schedule{DayOfWeek: 1, TimeOfDay: "23:00", Timezone: "UTC"} // 1 = Monday
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)              // Monday, 10:00 -- before 23:00
	_, ok := nextOccurrenceSince(sch, now)
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- today's occurrence time hasn't arrived yet")
	}
}

func TestNextOccurrenceSince_TimezoneConversion(t *testing.T) {
	// Friday 23:00 IST (Asia/Kolkata, UTC+5:30) is Friday 17:30 UTC.
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Asia/Kolkata"}
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC) // just after 17:30 UTC on that Friday
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true")
	}
	want := time.Date(2026, 8, 7, 17, 30, 0, 0, time.UTC)
	if !occurrence.Equal(want) {
		t.Errorf("occurrence = %v, want %v (UTC equivalent of Friday 23:00 IST)", occurrence, want)
	}
}

func TestNextOccurrenceSince_InvalidTimezone_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Not/A_Real_Zone"}
	_, ok := nextOccurrenceSince(sch, time.Now().UTC())
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false for an invalid timezone")
	}
}

func TestNextOccurrenceSince_InvalidTimeOfDay_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "not-a-time", Timezone: "UTC"}
	_, ok := nextOccurrenceSince(sch, time.Now().UTC())
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false for an invalid time-of-day")
	}
}
