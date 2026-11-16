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

// Filters on a daily window read the day the window STARTS, so an overnight window that began on a matching day
// still covers its after-midnight hours.

func TestBlackoutCovers_DailyWeekdays(t *testing.T) {
	w := Blackout{Kind: "daily", TimeFrom: "18:00", TimeTo: "23:00", Timezone: "UTC", Weekdays: "mon,tue,wed,thu,fri"}
	if !w.Covers(mustTime(t, "2026-12-04T19:00:00Z")) { // Friday
		t.Error("Friday 19:00 should be covered")
	}
	if w.Covers(mustTime(t, "2026-12-05T19:00:00Z")) { // Saturday
		t.Error("Saturday 19:00 should not be covered by a weekday window")
	}
	if w.Covers(mustTime(t, "2026-12-06T19:00:00Z")) { // Sunday
		t.Error("Sunday 19:00 should not be covered")
	}
}

func TestBlackoutCovers_DailyMonthDaysCountFromTheEnd(t *testing.T) {
	w := Blackout{Kind: "daily", TimeFrom: "00:00", TimeTo: "24:00", Timezone: "UTC", MonthDays: "-2,-1,1"}
	covered := []string{"2026-12-30T10:00:00Z", "2026-12-31T23:59:30Z", "2027-01-01T00:00:00Z", "2027-02-27T10:00:00Z", "2027-02-28T10:00:00Z", "2028-02-29T10:00:00Z"}
	for _, at := range covered {
		if !w.Covers(mustTime(t, at)) {
			t.Errorf("%s should be covered (month end or the 1st)", at)
		}
	}
	for _, at := range []string{"2026-12-29T10:00:00Z", "2027-01-02T10:00:00Z", "2027-02-26T10:00:00Z", "2028-02-27T10:00:00Z"} {
		if w.Covers(mustTime(t, at)) {
			t.Errorf("%s should not be covered", at)
		}
	}
}

func TestBlackoutCovers_OvernightFilterUsesTheStartDay(t *testing.T) {
	fri := Blackout{Kind: "daily", TimeFrom: "22:00", TimeTo: "06:00", Timezone: "UTC", Weekdays: "fri"}
	if !fri.Covers(mustTime(t, "2026-12-04T23:00:00Z")) { // Friday night
		t.Error("Friday 23:00 should be covered")
	}
	if !fri.Covers(mustTime(t, "2026-12-05T02:00:00Z")) { // Saturday 02:00 belongs to Friday's window
		t.Error("Saturday 02:00 belongs to the window that started Friday")
	}
	if fri.Covers(mustTime(t, "2026-12-04T02:00:00Z")) { // Friday 02:00 belongs to Thursday's window
		t.Error("Friday 02:00 belongs to Thursday's window and must not be covered")
	}
	if fri.Covers(mustTime(t, "2026-12-05T23:00:00Z")) {
		t.Error("Saturday 23:00 starts a Saturday window and must not be covered")
	}
	last := Blackout{Kind: "daily", TimeFrom: "22:00", TimeTo: "06:00", Timezone: "UTC", MonthDays: "-1"}
	if !last.Covers(mustTime(t, "2027-01-01T02:00:00Z")) { // belongs to Dec 31, the last day
		t.Error("Jan 1 02:00 belongs to the window that started on the last day of December")
	}
}

func TestBlackoutFilters_UseTheWindowTimezone(t *testing.T) {
	// 20:00 UTC Friday is already Saturday 01:30 in Kolkata.
	w := Blackout{Kind: "daily", TimeFrom: "00:00", TimeTo: "24:00", Timezone: "Asia/Kolkata", Weekdays: "fri"}
	if w.Covers(mustTime(t, "2026-12-04T20:00:00Z")) {
		t.Error("Friday 20:00Z is Saturday in Kolkata and must not match a Friday window")
	}
	if !w.Covers(mustTime(t, "2026-12-04T10:00:00Z")) {
		t.Error("Friday 10:00Z is Friday 15:30 in Kolkata and must match")
	}
}

func TestValidateBlackout_FilterAndAllDayRules(t *testing.T) {
	base := func() Blackout {
		return Blackout{Name: "n", Kind: "daily", TimeFrom: "18:00", TimeTo: "19:00", Timezone: "UTC"}
	}
	ok := base()
	ok.Weekdays, ok.MonthDays, ok.TimeFrom, ok.TimeTo = "Mon, fri", "1,-1,31,-31", "00:00", "24:00"
	if err := ValidateBlackout(ok); err != nil {
		t.Fatalf("a valid filtered all-day window was refused: %v", err)
	}
	bad := map[string]func(*Blackout){
		"unknown weekday":      func(b *Blackout) { b.Weekdays = "funday" },
		"month day zero":       func(b *Blackout) { b.MonthDays = "0" },
		"month day 32":         func(b *Blackout) { b.MonthDays = "32" },
		"month day -32":        func(b *Blackout) { b.MonthDays = "-32" },
		"month day not number": func(b *Blackout) { b.MonthDays = "last" },
		"24:00 as the start":   func(b *Blackout) { b.TimeFrom = "24:00" },
		"25:00 as the end":     func(b *Blackout) { b.TimeTo = "25:00" },
	}
	for name, mutate := range bad {
		b := base()
		mutate(&b)
		if err := ValidateBlackout(b); err == nil {
			t.Errorf("%s: window was accepted", name)
		}
	}
	once := Blackout{Name: "n", Kind: "once", Weekdays: "mon"}
	s, e := mustTime(t, "2026-12-31T00:00:00Z"), mustTime(t, "2027-01-01T00:00:00Z")
	once.StartsAt, once.EndsAt = &s, &e
	if err := ValidateBlackout(once); err == nil {
		t.Error("a once window with a weekday filter was accepted, but the filter would be ignored")
	}
}
