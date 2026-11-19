package db

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata" // zone data travels with the binary, so a minimal container can still resolve a timezone name
)

var clockRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// NormalizeClockDays checks a weekday list (three-letter lower-case names) and returns it comma-joined in week order.
// An empty list means every day.
func NormalizeClockDays(days []string) (string, error) {
	if len(days) > 7 {
		return "", errors.New("at most 7 days")
	}
	seen := map[time.Weekday]bool{}
	for _, d := range days {
		w, ok := weekdayNames[strings.ToLower(strings.TrimSpace(d))]
		if !ok {
			return "", fmt.Errorf("day %q must be one of sun, mon, tue, wed, thu, fri, sat", truncateText(d, 12))
		}
		seen[w] = true
	}
	var out []string
	for _, name := range []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"} {
		if seen[weekdayNames[name]] {
			out = append(out, name)
		}
	}
	return strings.Join(out, ","), nil
}

func truncateText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ValidateClock checks a time of day ("HH:MM", 24 hour) and a timezone name, and returns the location.
func ValidateClock(at, timezone string) (*time.Location, error) {
	if !clockRE.MatchString(at) {
		return nil, errors.New("at must be a time of day as HH:MM, 24 hour, for example 02:30")
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if len(timezone) > 64 {
		return nil, errors.New("timezone is too long")
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, errors.New("timezone must be an IANA name such as Asia/Kolkata or UTC")
	}
	return loc, nil
}

// NextClockRun returns the first moment after the given time that is at the clock time in the timezone, on one of the days (all days
// when empty). A local time that does not exist on a daylight-saving change runs at the moment the clock jumps to; one that happens
// twice runs at its first occurrence.
func NextClockRun(after time.Time, at, timezone, days string) (time.Time, error) {
	loc, err := ValidateClock(at, timezone)
	if err != nil {
		return time.Time{}, err
	}
	var hh, mm int
	_, _ = fmt.Sscanf(at, "%d:%d", &hh, &mm)
	allowed := map[time.Weekday]bool{}
	for _, d := range strings.Split(days, ",") {
		if w, ok := weekdayNames[d]; ok {
			allowed[w] = true
		}
	}
	local := after.In(loc)
	for i := 0; i <= 8; i++ {
		cand := time.Date(local.Year(), local.Month(), local.Day()+i, hh, mm, 0, 0, loc)
		if cand.Hour() != hh || cand.Minute() != mm {
			// The local time was skipped by a clock change and Go resolved it to the earlier side of the jump. Moving an hour on
			// lands just after the jump (the usual size of a daylight-saving change).
			cand = cand.Add(time.Hour)
		}
		if !cand.After(after) {
			continue
		}
		if len(allowed) > 0 && !allowed[cand.Weekday()] {
			continue
		}
		return cand.UTC(), nil
	}
	return time.Time{}, errors.New("no run time found")
}
