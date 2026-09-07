package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
	"time"
)

// Schedule is a recurring template that spawns a fresh one-shot Job each
// occurrence. It is not itself a Job -- it outlives any single spawned run.
type Schedule struct {
	ID               string
	Type             string
	Payload          json.RawMessage
	AgentIDs         []string
	DayOfWeek        int    // 0=Sunday .. 6=Saturday -- used when RecurrenceType is "" (alias for "weekly") or "weekly"
	TimeOfDay        string // "23:00", 24h HH:MM -- used by every RecurrenceType except "once"
	Timezone         string // IANA name, e.g. "Asia/Kolkata"
	Enabled          bool
	CreatedBy        string
	CreatedAt        time.Time
	LastOccurrenceAt *time.Time
	LastSpawnedJobID string

	// RecurrenceType is "" (alias for "weekly", the original behavior) |
	// "once" | "daily" | "weekly" | "monthly". See nextOccurrenceSince.
	RecurrenceType string
	RunAt          *time.Time // for RecurrenceType=="once": the single absolute fire time
	DayOfMonth     int        // for RecurrenceType=="monthly": 1-28
	EndDate        *time.Time // nil = no end; no spawns once now is after this

	// ConcurrencyLimit is copied onto every Job this schedule spawns (see
	// Store.CreateBatchWithConcurrency).
	ConcurrencyLimit int

	// GroupIDs are agent_groups.id values -- resolved recursively (a group
	// and all its descendants) fresh at every spawn, unioned with AgentIDs.
	// See Store.ResolveGroupAgentIDs.
	GroupIDs []int64

	// Mode/ApprovedBy/ApprovedAt/ApprovalVersion/Reason are the Scheduled
	// Execution Authorization for scheduled_assessment schedules ("" for
	// other schedule types like batch_remediation). Mode is "posture" (no
	// authorization needed) or "telemetry" (requires the four fields below,
	// captured once at creation -- schedules are immutable, so this can
	// never go stale).
	Mode            string
	ApprovedBy      string
	ApprovedAt      *time.Time
	ApprovalVersion int
	Reason          string

	// InitiativeID, when set, is auto-assigned to every Job this schedule
	// spawns (see Dispatcher.spawnDueSchedules) -- "" means unassigned, same
	// convention as jobs.Job.InitiativeID.
	InitiativeID string
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

// scheduleJitterWindow bounds how far a schedule's effective trigger time
// can drift from its nominal TimeOfDay -- small enough to stay well within
// user expectations of "9am daily", large enough to break up clusters of
// schedules sharing a common nominal time. See
// docs/superpowers/specs/2026-09-07-scheduled-assessment-jitter-design.md.
const scheduleJitterWindow = 2 * time.Minute

// jitterOffset derives a stable per-schedule offset in [-window, +window],
// deterministic from the schedule's own ID -- same offset every time this
// process (or any future process) computes it, no stored state, no
// reconciliation needed across restarts. Production schedules always have
// a real DB-assigned id (Store.CreateSchedule's `RETURNING id`); an empty
// ID is purely a test-fixture artifact, never a real production value.
func jitterOffset(scheduleID string, window time.Duration) time.Duration {
	h := fnv.New64a()
	h.Write([]byte(scheduleID))
	span := int64(2*window) + 1
	return time.Duration(int64(h.Sum64()%uint64(span))) - window
}

// nextOccurrenceSince finds the most recent past occurrence of sch's
// recurrence slot in sch.Timezone, and reports whether it is newer than
// sch.LastOccurrenceAt. ok=false is the common case (nothing new since the
// last check). RecurrenceType=="" aliases to "weekly" so every schedule row
// created before this field existed keeps behaving identically.
func nextOccurrenceSince(sch Schedule, now time.Time) (occurrence time.Time, ok bool) {
	if sch.EndDate != nil && now.After(*sch.EndDate) {
		return time.Time{}, false
	}
	loc, err := time.LoadLocation(sch.Timezone)
	if err != nil {
		return time.Time{}, false
	}

	recType := sch.RecurrenceType
	if recType == "" {
		recType = "weekly"
	}

	switch recType {
	case "once":
		return nextOccurrenceOnce(sch, now, loc)
	case "daily":
		return nextOccurrenceDaily(sch, now, loc)
	case "weekly":
		return nextOccurrenceWeekly(sch, now, loc)
	case "monthly":
		return nextOccurrenceMonthly(sch, now, loc)
	default:
		return time.Time{}, false
	}
}

func nextOccurrenceOnce(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	if sch.RunAt == nil || sch.LastOccurrenceAt != nil {
		return time.Time{}, false // no target time, or already spawned its one occurrence ever
	}
	candidate := sch.RunAt.In(loc)
	if candidate.After(now) {
		return time.Time{}, false
	}
	return candidate.UTC(), true
}

func nextOccurrenceDaily(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for daysBack := 0; daysBack < 2; daysBack++ {
		candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
		jittered := candidate.Add(jitterOffset(sch.ID, scheduleJitterWindow))
		if jittered.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !jittered.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return jittered.UTC(), true
	}
	return time.Time{}, false
}

func nextOccurrenceWeekly(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for daysBack := 0; daysBack < 7; daysBack++ {
		candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
		if int(candidate.Weekday()) != sch.DayOfWeek {
			continue
		}
		jittered := candidate.Add(jitterOffset(sch.ID, scheduleJitterWindow))
		if jittered.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !jittered.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return jittered.UTC(), true
	}
	return time.Time{}, false
}

func nextOccurrenceMonthly(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for monthsBack := 0; monthsBack < 2; monthsBack++ {
		// time.Date normalizes an out-of-range day (e.g. day 31 in a
		// 30-day month) by rolling into the next month -- the Day() check
		// below rejects that roll-over instead of misfiring in the wrong
		// month.
		candidate := time.Date(nowLocal.Year(), nowLocal.Month()-time.Month(monthsBack), sch.DayOfMonth, hh, mm, 0, 0, loc)
		if candidate.Day() != sch.DayOfMonth {
			continue
		}
		jittered := candidate.Add(jitterOffset(sch.ID, scheduleJitterWindow))
		if jittered.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !jittered.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return jittered.UTC(), true
	}
	return time.Time{}, false
}

const scheduleColumns = `id, type, payload, agent_ids, day_of_week, time_of_day, timezone, enabled, created_by, created_at, last_occurrence_at, last_spawned_job_id, recurrence_type, run_at, day_of_month, end_date, concurrency_limit, group_ids, mode, approved_by, approved_at, approval_version, reason, initiative_id`

func scanSchedule(row interface {
	Scan(dest ...any) error
}) (Schedule, error) {
	var sch Schedule
	var agentIDsRaw, groupIDsRaw []byte
	err := row.Scan(&sch.ID, &sch.Type, &sch.Payload, &agentIDsRaw, &sch.DayOfWeek, &sch.TimeOfDay,
		&sch.Timezone, &sch.Enabled, &sch.CreatedBy, &sch.CreatedAt, &sch.LastOccurrenceAt, &sch.LastSpawnedJobID,
		&sch.RecurrenceType, &sch.RunAt, &sch.DayOfMonth, &sch.EndDate, &sch.ConcurrencyLimit, &groupIDsRaw,
		&sch.Mode, &sch.ApprovedBy, &sch.ApprovedAt, &sch.ApprovalVersion, &sch.Reason, &sch.InitiativeID)
	if err != nil {
		return Schedule{}, err
	}
	if err := json.Unmarshal(agentIDsRaw, &sch.AgentIDs); err != nil {
		return Schedule{}, err
	}
	if err := json.Unmarshal(groupIDsRaw, &sch.GroupIDs); err != nil {
		return Schedule{}, err
	}
	return sch, nil
}

func (s *Store) CreateSchedule(ctx context.Context, sch Schedule) (Schedule, error) {
	agentIDsJSON, err := json.Marshal(sch.AgentIDs)
	if err != nil {
		return Schedule{}, err
	}
	groupIDsJSON, err := json.Marshal(sch.GroupIDs)
	if err != nil {
		return Schedule{}, err
	}
	var id string
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO job_schedules (type, payload, agent_ids, day_of_week, time_of_day, timezone, enabled, created_by,
		    recurrence_type, run_at, day_of_month, end_date, concurrency_limit, group_ids, mode, approved_by, approved_at, approval_version, reason, initiative_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) RETURNING id`,
		sch.Type, []byte(sch.Payload), agentIDsJSON, sch.DayOfWeek, sch.TimeOfDay, sch.Timezone, sch.Enabled, sch.CreatedBy,
		sch.RecurrenceType, sch.RunAt, sch.DayOfMonth, sch.EndDate, sch.ConcurrencyLimit, groupIDsJSON,
		sch.Mode, sch.ApprovedBy, sch.ApprovedAt, sch.ApprovalVersion, sch.Reason, sch.InitiativeID,
	).Scan(&id); err != nil {
		return Schedule{}, err
	}
	return s.GetSchedule(ctx, id)
}

// UpdateSchedule replaces every editable field on schedule id. Identity
// fields (id, type, created_by, created_at) and spawner-owned bookkeeping
// (last_occurrence_at, last_spawned_job_id) are never touched here -- only
// Store.MarkScheduleOccurrenceHandled writes those. See
// docs/superpowers/specs/2026-08-11-scheduled-assessment-edit-design.md.
func (s *Store) UpdateSchedule(ctx context.Context, id string, sch Schedule) (Schedule, error) {
	agentIDsJSON, err := json.Marshal(sch.AgentIDs)
	if err != nil {
		return Schedule{}, err
	}
	groupIDsJSON, err := json.Marshal(sch.GroupIDs)
	if err != nil {
		return Schedule{}, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE job_schedules SET
		    payload=$1, agent_ids=$2, group_ids=$3, day_of_week=$4, time_of_day=$5, timezone=$6, enabled=$7,
		    recurrence_type=$8, run_at=$9, day_of_month=$10, end_date=$11, concurrency_limit=$12,
		    mode=$13, approved_by=$14, approved_at=$15, approval_version=$16, reason=$17, initiative_id=$18
		 WHERE id=$19`,
		[]byte(sch.Payload), agentIDsJSON, groupIDsJSON, sch.DayOfWeek, sch.TimeOfDay, sch.Timezone, sch.Enabled,
		sch.RecurrenceType, sch.RunAt, sch.DayOfMonth, sch.EndDate, sch.ConcurrencyLimit,
		sch.Mode, sch.ApprovedBy, sch.ApprovedAt, sch.ApprovalVersion, sch.Reason, sch.InitiativeID, id,
	); err != nil {
		return Schedule{}, err
	}
	return s.GetSchedule(ctx, id)
}

func (s *Store) GetSchedule(ctx context.Context, id string) (Schedule, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scheduleColumns+` FROM job_schedules WHERE id=$1`, id)
	return scanSchedule(row)
}

func (s *Store) ListEnabledSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleColumns+` FROM job_schedules WHERE enabled = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleColumns+` FROM job_schedules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func (s *Store) DisableSchedule(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE job_schedules SET enabled=false WHERE id=$1`, id)
	return err
}

func (s *Store) MarkScheduleOccurrenceHandled(ctx context.Context, id string, occurrence time.Time, spawnedJobID string) error {
	if spawnedJobID == "" {
		_, err := s.pool.Exec(ctx, `UPDATE job_schedules SET last_occurrence_at=$1 WHERE id=$2`, occurrence, id)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE job_schedules SET last_occurrence_at=$1, last_spawned_job_id=$2 WHERE id=$3`,
		occurrence, spawnedJobID, id)
	return err
}
