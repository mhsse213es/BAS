package jobs

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Schedule is a recurring template that spawns a fresh one-shot Job each
// weekly occurrence. It is not itself a Job -- it outlives any single
// spawned run.
type Schedule struct {
	ID               string
	Type             string
	Payload          json.RawMessage
	AgentIDs         []string
	DayOfWeek        int    // 0=Sunday .. 6=Saturday
	TimeOfDay        string // "23:00", 24h HH:MM
	Timezone         string // IANA name, e.g. "Asia/Kolkata"
	Enabled          bool
	CreatedBy        string
	CreatedAt        time.Time
	LastOccurrenceAt *time.Time
	LastSpawnedJobID string
}

var errInvalidTimeOfDay = errors.New("invalid time-of-day, want HH:MM")

// parseTimeOfDay parses "HH:MM" (24h) into hour/minute, rejecting anything
// else so an invalid schedule can never silently compute a wrong time.
func parseTimeOfDay(s string) (hour, minute int, err error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, errInvalidTimeOfDay
	}
	hour, err = strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return 0, 0, errInvalidTimeOfDay
	}
	minute, err = strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return 0, 0, errInvalidTimeOfDay
	}
	return hour, minute, nil
}

// nextOccurrenceSince finds the most recent past occurrence of sch's weekly
// (DayOfWeek, TimeOfDay) slot in sch.Timezone, and reports whether it is
// newer than sch.LastOccurrenceAt. ok=false is the common case (nothing new
// since the last check).
func nextOccurrenceSince(sch Schedule, now time.Time) (occurrence time.Time, ok bool) {
	loc, err := time.LoadLocation(sch.Timezone)
	if err != nil {
		return time.Time{}, false
	}
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for daysBack := 0; daysBack < 7; daysBack++ {
		candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
		if int(candidate.Weekday()) != sch.DayOfWeek || candidate.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !candidate.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return candidate.UTC(), true
	}
	return time.Time{}, false
}
