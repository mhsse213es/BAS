package jobs

import (
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

// A once window covers [starts_at, ends_at): the start is inside, the end is not.
func TestBlackoutCovers_Once(t *testing.T) {
	start := mustTime(t, "2026-12-31T00:00:00Z")
	end := mustTime(t, "2027-01-02T00:00:00Z")
	w := Blackout{Kind: "once", StartsAt: &start, EndsAt: &end}
	cases := map[string]bool{
		"2026-12-30T23:59:59Z": false,
		"2026-12-31T00:00:00Z": true,
		"2027-01-01T12:00:00Z": true,
		"2027-01-02T00:00:00Z": false,
	}
	for at, want := range cases {
		if got := w.Covers(mustTime(t, at)); got != want {
			t.Errorf("once.Covers(%s) = %v, want %v", at, got, want)
		}
	}
}

// A daily window is read in its own timezone: 18:00-19:00 IST is 12:30-13:30 UTC.
func TestBlackoutCovers_DailyTimezone(t *testing.T) {
	w := Blackout{Kind: "daily", TimeFrom: "18:00", TimeTo: "19:00", Timezone: "Asia/Kolkata"}
	if !w.Covers(mustTime(t, "2026-12-01T12:30:00Z")) {
		t.Error("12:30Z is 18:00 IST, inside the window")
	}
	if w.Covers(mustTime(t, "2026-12-01T13:30:00Z")) {
		t.Error("13:30Z is 19:00 IST, the end is outside")
	}
	if w.Covers(mustTime(t, "2026-12-01T10:00:00Z")) {
		t.Error("10:00Z is 15:30 IST, outside")
	}
}

// A window whose from is later than its to crosses midnight (end-of-day batch 22:00-06:00).
func TestBlackoutCovers_DailyCrossesMidnight(t *testing.T) {
	w := Blackout{Kind: "daily", TimeFrom: "22:00", TimeTo: "06:00", Timezone: "UTC"}
	for _, at := range []string{"2026-12-01T22:00:00Z", "2026-12-01T23:30:00Z", "2026-12-02T05:59:00Z"} {
		if !w.Covers(mustTime(t, at)) {
			t.Errorf("%s should be inside 22:00-06:00", at)
		}
	}
	for _, at := range []string{"2026-12-02T06:00:00Z", "2026-12-01T12:00:00Z"} {
		if w.Covers(mustTime(t, at)) {
			t.Errorf("%s should be outside 22:00-06:00", at)
		}
	}
}

// A date range limits a daily window to those dates in its timezone, inclusive at both ends.
func TestBlackoutCovers_DailyDateRange(t *testing.T) {
	w := Blackout{Kind: "daily", TimeFrom: "00:00", TimeTo: "23:59", Timezone: "UTC",
		ValidFrom: "2026-12-29", ValidTo: "2026-12-31"}
	cases := map[string]bool{
		"2026-12-28T12:00:00Z": false,
		"2026-12-29T00:00:00Z": true,
		"2026-12-31T23:00:00Z": true,
		"2027-01-01T00:00:00Z": false,
	}
	for at, want := range cases {
		if got := w.Covers(mustTime(t, at)); got != want {
			t.Errorf("date-range.Covers(%s) = %v, want %v", at, got, want)
		}
	}
}

func TestCoveringBlackout_ReturnsTheMatch(t *testing.T) {
	start := mustTime(t, "2026-12-31T00:00:00Z")
	end := mustTime(t, "2027-01-02T00:00:00Z")
	windows := []Blackout{
		{Name: "RBI reporting", Kind: "once", StartsAt: &start, EndsAt: &end},
		{Name: "EoD batch", Kind: "daily", TimeFrom: "18:00", TimeTo: "19:00", Timezone: "UTC"},
	}
	w, ok := CoveringBlackout(windows, mustTime(t, "2026-12-30T18:30:00Z"))
	if !ok || w.Name != "EoD batch" {
		t.Errorf("got (%q, %v), want the EoD batch window", w.Name, ok)
	}
	if _, ok := CoveringBlackout(windows, mustTime(t, "2026-12-30T10:00:00Z")); ok {
		t.Error("nothing covers 2026-12-30 10:00Z")
	}
}

func TestValidateBlackout(t *testing.T) {
	start := mustTime(t, "2026-12-31T00:00:00Z")
	end := mustTime(t, "2027-01-02T00:00:00Z")
	bad := map[string]Blackout{
		"no name":               {Kind: "once", StartsAt: &start, EndsAt: &end},
		"unknown kind":          {Name: "x", Kind: "weekly"},
		"once without end":      {Name: "x", Kind: "once", StartsAt: &start},
		"once end before start": {Name: "x", Kind: "once", StartsAt: &end, EndsAt: &start},
		"daily bad timezone":    {Name: "x", Kind: "daily", TimeFrom: "18:00", TimeTo: "19:00", Timezone: "Mars/Olympus"},
		"daily bad time":        {Name: "x", Kind: "daily", TimeFrom: "25:00", TimeTo: "19:00", Timezone: "UTC"},
		"daily from equals to":  {Name: "x", Kind: "daily", TimeFrom: "18:00", TimeTo: "18:00", Timezone: "UTC"},
		"daily range reversed": {Name: "x", Kind: "daily", TimeFrom: "18:00", TimeTo: "19:00", Timezone: "UTC",
			ValidFrom: "2026-12-31", ValidTo: "2026-12-01"},
	}
	for name, b := range bad {
		if err := ValidateBlackout(b); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	good := Blackout{Name: "Month-end freeze", Kind: "daily", TimeFrom: "00:00", TimeTo: "23:59", Timezone: "Asia/Kolkata",
		ValidFrom: "2026-12-29", ValidTo: "2027-01-02"}
	if err := ValidateBlackout(good); err != nil {
		t.Errorf("valid window refused: %v", err)
	}
}
