package db

import (
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNextClockRun(t *testing.T) {
	for _, tc := range []struct {
		name, after, at, tz, days, want string
	}{
		{"later today in UTC", "2026-11-10T01:00:00Z", "02:30", "UTC", "", "2026-11-10T02:30:00Z"},
		{"already passed, so tomorrow", "2026-11-10T03:00:00Z", "02:30", "UTC", "", "2026-11-11T02:30:00Z"},
		{"exactly at the time is not after it", "2026-11-10T02:30:00Z", "02:30", "UTC", "", "2026-11-11T02:30:00Z"},
		{"empty timezone is UTC", "2026-11-10T01:00:00Z", "02:30", "", "", "2026-11-10T02:30:00Z"},
		// 02:30 in India (UTC+5:30, no daylight saving) is 21:00 UTC the day before.
		{"Asia/Kolkata", "2026-11-10T00:00:00Z", "02:30", "Asia/Kolkata", "", "2026-11-10T21:00:00Z"},
		// 10 Nov 2026 is a Tuesday. Weekdays only, asked on Friday evening: next is Monday.
		{"weekdays skip the weekend", "2026-11-13T23:00:00Z", "02:30", "UTC", "mon,tue,wed,thu,fri", "2026-11-16T02:30:00Z"},
		{"one day a week", "2026-11-10T00:00:00Z", "09:00", "UTC", "sun", "2026-11-15T09:00:00Z"},
		// New York ends daylight saving on 1 Nov 2026 (UTC-4 to UTC-5): 09:00 local is 13:00 UTC before, 14:00 UTC after.
		{"before the clocks change", "2026-10-31T00:00:00Z", "09:00", "America/New_York", "", "2026-10-31T13:00:00Z"},
		{"after the clocks change", "2026-11-02T00:00:00Z", "09:00", "America/New_York", "", "2026-11-02T14:00:00Z"},
		// On 8 Mar 2026 02:30 does not exist in New York (clocks jump from 02:00 to 03:00): it runs at the jump, 03:30 local = 07:30 UTC.
		{"time that does not exist", "2026-03-08T00:00:00Z", "02:30", "America/New_York", "", "2026-03-08T07:30:00Z"},
		// 1 Nov 2026 01:30 happens twice in New York: the first one, 05:30 UTC (EDT).
		{"time that happens twice", "2026-11-01T00:00:00Z", "01:30", "America/New_York", "", "2026-11-01T05:30:00Z"},
	} {
		got, err := NextClockRun(mustTime(t, tc.after), tc.at, tc.tz, tc.days)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !got.Equal(mustTime(t, tc.want)) {
			t.Errorf("%s: got %s, want %s", tc.name, got.Format(time.RFC3339), tc.want)
		}
	}
}

func TestClockValidation(t *testing.T) {
	for _, at := range []string{"", "2:30", "24:00", "12:60", "12:5", "ab:cd", "12:30:00", " 12:30", "12:30 "} {
		if _, err := ValidateClock(at, "UTC"); err == nil {
			t.Errorf("time %q was accepted", at)
		}
	}
	for _, tz := range []string{"Mars/Base", "../etc/passwd", "utc+5", strings.Repeat("A", 65)} {
		if _, err := ValidateClock("02:30", tz); err == nil {
			t.Errorf("timezone %q was accepted", tz)
		}
	}
	for _, d := range [][]string{{"monday"}, {"xyz"}, {""}, {"mon", "mon", "tue", "wed", "thu", "fri", "sat", "sun"}} {
		if _, err := NormalizeClockDays(d); err == nil {
			t.Errorf("days %v were accepted", d)
		}
	}
	got, err := NormalizeClockDays([]string{"Fri", "mon", "mon"})
	if err != nil || got != "mon,fri" {
		t.Errorf("days normalised to %q (%v), want mon,fri", got, err)
	}
	if got, _ := NormalizeClockDays(nil); got != "" {
		t.Errorf("no days: %q, want every day", got)
	}
}
