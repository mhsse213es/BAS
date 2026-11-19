package jobs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Blackout is a change-freeze window: a time when scheduled assessments must not start. Two kinds:
//
//   - "once": covers [StartsAt, EndsAt). Use it for a single date range, such as a regulatory reporting
//     window or a month-end freeze.
//   - "daily": covers TimeFrom..TimeTo every day in Timezone (for example an end-of-day or beginning-of-day batch).
//     TimeFrom later than TimeTo is a window that crosses midnight, such as 22:00..06:00. ValidFrom and ValidTo
//     (YYYY-MM-DD, in Timezone, inclusive) limit the days it applies to; empty means no limit on that side.
//
// Two optional filters narrow a daily window to certain days, read in Timezone on the day the window starts:
// Weekdays (for example "mon,tue,wed,thu,fri" for a business-day batch) and MonthDays (for example "-2,-1,1" for the
// last two days of the month and the first). TimeTo may be "24:00" so a window can cover whole days.
//
// A scheduled occurrence inside any window is skipped, not deferred. The spawner records it as handled with no job,
// so the schedule resumes at its next occurrence. Scheduled assessments are the only thing blocked here; a run started
// by hand is not.
type Blackout struct {
	ID        string
	Name      string
	Kind      string // "once" | "daily"
	StartsAt  *time.Time
	EndsAt    *time.Time
	TimeFrom  string // "HH:MM", daily only
	TimeTo    string // "HH:MM", daily only
	Timezone  string // IANA name, daily only
	ValidFrom string // YYYY-MM-DD, daily only, optional
	ValidTo   string // YYYY-MM-DD, daily only, optional
	Weekdays  string // daily only, optional: comma list of mon,tue,wed,thu,fri,sat,sun; empty means every day
	MonthDays string // daily only, optional: comma list of day numbers 1..31, or -1..-31 from the end (-1 is the last day); empty means every day
	CreatedBy string
	CreatedAt time.Time
}

// ErrInvalidBlackout marks a window that failed ValidateBlackout, so the API can answer 400 rather than 500.
var ErrInvalidBlackout = errors.New("invalid blackout window")

var errInvalidBlackout = ErrInvalidBlackout

// ValidateBlackout rejects a window that could not be read correctly. A bad window is refused when it is created,
// rather than silently covering nothing or everything.
func ValidateBlackout(b Blackout) error {
	if strings.TrimSpace(b.Name) == "" {
		return fmt.Errorf("%w: name is required", errInvalidBlackout)
	}
	switch b.Kind {
	case "once":
		if b.StartsAt == nil || b.EndsAt == nil {
			return fmt.Errorf("%w: a once window needs starts_at and ends_at", errInvalidBlackout)
		}
		if !b.EndsAt.After(*b.StartsAt) {
			return fmt.Errorf("%w: ends_at must be after starts_at", errInvalidBlackout)
		}
	case "daily":
		if b.Timezone == "" {
			return fmt.Errorf("%w: a daily window needs a timezone", errInvalidBlackout)
		}
		if _, err := time.LoadLocation(b.Timezone); err != nil {
			return fmt.Errorf("%w: unknown timezone %q", errInvalidBlackout, b.Timezone)
		}
		from, err := minutesOfDay(b.TimeFrom)
		if err != nil {
			return fmt.Errorf("%w: time_from must be HH:MM", errInvalidBlackout)
		}
		to, err := endMinutesOfDay(b.TimeTo)
		if err != nil {
			return fmt.Errorf("%w: time_to must be HH:MM, or 24:00 for the end of the day", errInvalidBlackout)
		}
		if from == to {
			return fmt.Errorf("%w: time_from and time_to must differ", errInvalidBlackout)
		}
		if err := validDate(b.ValidFrom); err != nil {
			return err
		}
		if err := validDate(b.ValidTo); err != nil {
			return err
		}
		if b.ValidFrom != "" && b.ValidTo != "" && b.ValidTo < b.ValidFrom {
			return fmt.Errorf("%w: valid_to is before valid_from", errInvalidBlackout)
		}
		if _, err := parseWeekdays(b.Weekdays); err != nil {
			return err
		}
		if _, err := parseMonthDays(b.MonthDays); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: kind must be once or daily", errInvalidBlackout)
	}
	if b.Kind == "once" && (strings.TrimSpace(b.Weekdays) != "" || strings.TrimSpace(b.MonthDays) != "") {
		return fmt.Errorf("%w: weekdays and month_days apply to daily windows only", errInvalidBlackout)
	}
	return nil
}

// endMinutesOfDay is minutesOfDay for the end of a window, which may be "24:00" (the end of the day, so a window can
// cover a whole day with no uncovered minute).
func endMinutesOfDay(s string) (int, error) {
	if s == "24:00" {
		return 24 * 60, nil
	}
	return minutesOfDay(s)
}

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// parseWeekdays reads a comma list such as "mon, fri". Empty means no filter (nil).
func parseWeekdays(s string) (map[time.Weekday]bool, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := map[time.Weekday]bool{}
	for _, tok := range strings.Split(s, ",") {
		d, ok := weekdayNames[strings.ToLower(strings.TrimSpace(tok))]
		if !ok {
			return nil, fmt.Errorf("%w: weekday %q is not one of mon,tue,wed,thu,fri,sat,sun", errInvalidBlackout, strings.TrimSpace(tok))
		}
		out[d] = true
	}
	return out, nil
}

// parseMonthDays reads a comma list of 1..31 or -1..-31. Empty means no filter (nil).
func parseMonthDays(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, tok := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(tok))
		if err != nil || n == 0 || n > 31 || n < -31 {
			return nil, fmt.Errorf("%w: month day %q must be 1..31, or -1..-31 counted from the end of the month", errInvalidBlackout, strings.TrimSpace(tok))
		}
		out = append(out, n)
	}
	return out, nil
}

// matchesMonthDay reports whether the date is one of the listed days; a negative n counts from the end of its month.
func matchesMonthDay(days []int, d time.Time) bool {
	last := time.Date(d.Year(), d.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
	for _, n := range days {
		if n == d.Day() || (n < 0 && last+n+1 == d.Day()) {
			return true
		}
	}
	return false
}

func validDate(s string) error {
	if s == "" {
		return nil
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return fmt.Errorf("%w: dates must be YYYY-MM-DD", errInvalidBlackout)
	}
	return nil
}

// minutesOfDay parses "HH:MM" into minutes after midnight.
func minutesOfDay(s string) (int, error) {
	h, m, err := parseTimeOfDay(s)
	if err != nil {
		return 0, err
	}
	return h*60 + m, nil
}

// Covers reports whether instant t falls inside the window. An invalid window covers nothing.
func (b Blackout) Covers(t time.Time) bool {
	switch b.Kind {
	case "once":
		if b.StartsAt == nil || b.EndsAt == nil {
			return false
		}
		return !t.Before(*b.StartsAt) && t.Before(*b.EndsAt)
	case "daily":
		loc, err := time.LoadLocation(b.Timezone)
		if err != nil {
			return false
		}
		local := t.In(loc)
		// The date range is read on the local date of the instant, so a window that crosses midnight is judged by the
		// day its time falls on.
		day := local.Format("2006-01-02")
		if b.ValidFrom != "" && day < b.ValidFrom {
			return false
		}
		if b.ValidTo != "" && day > b.ValidTo {
			return false
		}
		from, err1 := minutesOfDay(b.TimeFrom)
		to, err2 := endMinutesOfDay(b.TimeTo)
		if err1 != nil || err2 != nil {
			return false
		}
		m := local.Hour()*60 + local.Minute()
		inside := m >= from && m < to
		if from > to {
			inside = m >= from || m < to
		}
		if !inside {
			return false
		}
		// The weekday and month-day filters read the day the window started. For a window that crosses midnight,
		// the hours after midnight belong to the previous day's window.
		start := local
		if from > to && m < to {
			start = local.AddDate(0, 0, -1)
		}
		if wd, err := parseWeekdays(b.Weekdays); err != nil || (wd != nil && !wd[start.Weekday()]) {
			return false
		}
		if md, err := parseMonthDays(b.MonthDays); err != nil || (md != nil && !matchesMonthDay(md, start)) {
			return false
		}
		return true
	}
	return false
}

// CoveringBlackout returns the first window that covers t, for the message that says why a run was skipped.
func CoveringBlackout(windows []Blackout, t time.Time) (Blackout, bool) {
	for _, w := range windows {
		if w.Covers(t) {
			return w, true
		}
	}
	return Blackout{}, false
}

// CreateBlackout stores a window after ValidateBlackout has accepted it.
func (s *Store) CreateBlackout(ctx context.Context, b Blackout) (Blackout, error) {
	if err := ValidateBlackout(b); err != nil {
		return Blackout{}, err
	}
	var id string
	var createdAt time.Time
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO scheduled_blackouts (name, kind, starts_at, ends_at, time_from, time_to, timezone,
		     valid_from, valid_to, weekdays, month_days, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, '')::date, NULLIF($9, '')::date, $10, $11, $12)
		 RETURNING id, created_at`,
		b.Name, b.Kind, b.StartsAt, b.EndsAt, b.TimeFrom, b.TimeTo, b.Timezone, b.ValidFrom, b.ValidTo,
		strings.TrimSpace(b.Weekdays), strings.TrimSpace(b.MonthDays), b.CreatedBy,
	).Scan(&id, &createdAt); err != nil {
		return Blackout{}, err
	}
	b.ID = id
	b.CreatedAt = createdAt
	return b, nil
}

// ListBlackouts returns every window, newest first.
func (s *Store) ListBlackouts(ctx context.Context) ([]Blackout, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, kind, starts_at, ends_at, time_from, time_to, timezone,
		        COALESCE(valid_from::text, ''), COALESCE(valid_to::text, ''), weekdays, month_days, created_by, created_at
		 FROM scheduled_blackouts ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Blackout
	for rows.Next() {
		var b Blackout
		if err := rows.Scan(&b.ID, &b.Name, &b.Kind, &b.StartsAt, &b.EndsAt, &b.TimeFrom, &b.TimeTo, &b.Timezone,
			&b.ValidFrom, &b.ValidTo, &b.Weekdays, &b.MonthDays, &b.CreatedBy, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBlackout removes a window. It reports false when no window has that id.
func (s *Store) DeleteBlackout(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scheduled_blackouts WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
