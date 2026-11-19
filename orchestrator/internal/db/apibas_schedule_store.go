package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAPIBASScheduleNotFound means the target has no schedule.
var ErrAPIBASScheduleNotFound = errors.New("apibas schedule not found")

// APIBASScheduleMaxFailures is how many submissions in a row may fail before the schedule pauses itself. A failure here is a job
// that could not be queued (stale test data, a disabled target, a missing credential), not a job that ran and found problems.
const APIBASScheduleMaxFailures = 5

// APIBASSchedule runs a target's stored test data on a fixed interval. One schedule per target. Runs are lab and staging only and
// go through the same submission checks as a manual run.
type APIBASSchedule struct {
	TargetID   string
	EveryHours int
	// AtTime, Timezone and Days make a time-of-day schedule: run at AtTime ("HH:MM") in Timezone on Days (comma-joined weekday names,
	// empty for every day). When AtTime is set EveryHours is stored as 24 and not used.
	AtTime              string
	Timezone            string
	Days                string
	IncludeWrites       bool // false: write scenarios in the stored test data are left out of scheduled runs
	Enabled             bool
	NextRunAt           time.Time
	CreatedBy           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastRunAt           *time.Time
	LastJobID           string
	LastResult          string
	ConsecutiveFailures int
	// DueAt is set only on a schedule returned by ClaimDueAPIBASSchedules: the time the run was due, used to key the job.
	DueAt time.Time
}

const apibasScheduleColumns = `target_id, every_hours, include_writes, enabled, next_run_at, created_by, created_at, updated_at, last_run_at, last_job_id, last_result, consecutive_failures, at_time, timezone, run_days`

func scanAPIBASSchedule(row pgx.Row, extra ...any) (APIBASSchedule, error) {
	var s APIBASSchedule
	dest := append([]any{&s.TargetID, &s.EveryHours, &s.IncludeWrites, &s.Enabled, &s.NextRunAt, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
		&s.LastRunAt, &s.LastJobID, &s.LastResult, &s.ConsecutiveFailures, &s.AtTime, &s.Timezone, &s.Days}, extra...)
	err := row.Scan(dest...)
	return s, err
}

// PutAPIBASSchedule stores or replaces the target's schedule. The first run is NextRunAt. Replacing a schedule clears its failure
// count and, with Enabled, resumes it. The target row is locked so a concurrent delete cannot orphan the schedule.
func PutAPIBASSchedule(ctx context.Context, pool *pgxpool.Pool, rec APIBASSchedule) (APIBASSchedule, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return rec, fmt.Errorf("begin schedule save: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked string
	if err := tx.QueryRow(ctx, `SELECT id FROM apibas_targets WHERE id = $1 FOR UPDATE`, rec.TargetID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return rec, ErrAPIBASTargetNotFound
	} else if err != nil {
		return rec, fmt.Errorf("lock apibas target: %w", err)
	}
	out, err := scanAPIBASSchedule(tx.QueryRow(ctx, `
		INSERT INTO apibas_schedules (target_id, every_hours, include_writes, enabled, next_run_at, created_by, at_time, timezone, run_days)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (target_id) DO UPDATE
		   SET every_hours = EXCLUDED.every_hours, include_writes = EXCLUDED.include_writes, enabled = EXCLUDED.enabled,
		       at_time = EXCLUDED.at_time, timezone = EXCLUDED.timezone, run_days = EXCLUDED.run_days,
		       next_run_at = EXCLUDED.next_run_at, created_by = EXCLUDED.created_by, updated_at = NOW(), consecutive_failures = 0
		RETURNING `+apibasScheduleColumns, rec.TargetID, rec.EveryHours, rec.IncludeWrites, rec.Enabled, rec.NextRunAt, rec.CreatedBy, rec.AtTime, rec.Timezone, rec.Days))
	if err != nil {
		return rec, fmt.Errorf("save apibas schedule: %w", err)
	}
	return out, tx.Commit(ctx)
}

// GetAPIBASSchedule returns the target's schedule.
func GetAPIBASSchedule(ctx context.Context, pool *pgxpool.Pool, targetID string) (APIBASSchedule, error) {
	s, err := scanAPIBASSchedule(pool.QueryRow(ctx, `SELECT `+apibasScheduleColumns+` FROM apibas_schedules WHERE target_id = $1`, targetID))
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrAPIBASScheduleNotFound
	}
	if err != nil {
		return s, fmt.Errorf("read apibas schedule: %w", err)
	}
	return s, nil
}

// DeleteAPIBASSchedule removes the target's schedule and reports whether one existed.
func DeleteAPIBASSchedule(ctx context.Context, pool *pgxpool.Pool, targetID string) (bool, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM apibas_schedules WHERE target_id = $1`, targetID)
	if err != nil {
		return false, fmt.Errorf("delete apibas schedule: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ClaimDueAPIBASSchedules returns up to limit enabled schedules whose run is due at now, and moves each one's next run to now plus
// its interval in the same statement. A run missed while the server was down is run once, not made up. Rows are claimed with SKIP
// LOCKED, so two orchestrators never claim the same run, and each returned schedule carries the time it was due (DueAt) so the job
// key is the same wherever it is derived.
func ClaimDueAPIBASSchedules(ctx context.Context, pool *pgxpool.Pool, now time.Time, limit int) ([]APIBASSchedule, error) {
	due, _, err := ClaimDueAPIBASSchedulesReportingPauses(ctx, pool, now, limit)
	return due, err
}

// ClaimDueAPIBASSchedulesReportingPauses is ClaimDueAPIBASSchedules that also returns the schedules it paused because their clock
// settings could not be read, each with LastResult set to the reason, so the caller can tell someone.
func ClaimDueAPIBASSchedulesReportingPauses(ctx context.Context, pool *pgxpool.Pool, now time.Time, limit int) (due, paused []APIBASSchedule, err error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT `+apibasScheduleColumns+` FROM apibas_schedules
		 WHERE enabled AND next_run_at <= $1 ORDER BY next_run_at LIMIT $2 FOR UPDATE SKIP LOCKED`, now, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("claim apibas schedules: %w", err)
	}
	var out []APIBASSchedule
	for rows.Next() {
		s, err := scanAPIBASSchedule(rows)
		if err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan apibas schedule: %w", err)
		}
		out = append(out, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for i := range out {
		s := &out[i]
		s.DueAt = s.NextRunAt
		next := now.Add(time.Duration(s.EveryHours) * time.Hour)
		if s.AtTime != "" {
			// A schedule whose clock settings can no longer be read is paused rather than run at a guessed time.
			n, cerr := NextClockRun(now, s.AtTime, s.Timezone, s.Days)
			if cerr != nil {
				reason := "paused: " + truncateText(cerr.Error(), 200)
				if _, err := tx.Exec(ctx, `UPDATE apibas_schedules SET enabled = false, last_result = $2 WHERE target_id = $1`, s.TargetID, reason); err != nil {
					return nil, nil, fmt.Errorf("pause apibas schedule: %w", err)
				}
				s.LastResult, s.Enabled = reason, false
				paused = append(paused, *s)
				out = append(out[:i], out[i+1:]...)
				i--
				continue
			}
			next = n
		}
		s.NextRunAt = next
		if _, err := tx.Exec(ctx, `UPDATE apibas_schedules SET next_run_at = $2, last_run_at = $3 WHERE target_id = $1`, s.TargetID, next, now); err != nil {
			return nil, nil, fmt.Errorf("advance apibas schedule: %w", err)
		}
	}
	return out, paused, tx.Commit(ctx)
}

// RecordAPIBASScheduleResult stores what a scheduled run did. A failure to queue the job counts toward pausing the schedule, which
// pauses itself at APIBASScheduleMaxFailures in a row so a broken schedule does not retry for ever. A success resets the count.
func RecordAPIBASScheduleResult(ctx context.Context, pool *pgxpool.Pool, targetID, jobID, result string, failed bool) error {
	_, err := RecordAPIBASScheduleOutcome(ctx, pool, targetID, jobID, result, failed)
	return err
}

// RecordAPIBASScheduleOutcome is RecordAPIBASScheduleResult that also reports whether this call is the one that paused the schedule
// (it was enabled before and is not now), so a pause is announced once. The row is locked while it is read and changed.
func RecordAPIBASScheduleOutcome(ctx context.Context, pool *pgxpool.Pool, targetID, jobID, result string, failed bool) (paused bool, err error) {
	err = pool.QueryRow(ctx, `
		WITH old AS (SELECT enabled FROM apibas_schedules WHERE target_id = $1 FOR UPDATE)
		UPDATE apibas_schedules s
		   SET last_job_id = $2, last_result = $3,
		       consecutive_failures = CASE WHEN $4 THEN s.consecutive_failures + 1 ELSE 0 END,
		       enabled = CASE WHEN $4 AND s.consecutive_failures + 1 >= $5 THEN false ELSE s.enabled END
		  FROM old
		 WHERE s.target_id = $1
		RETURNING old.enabled AND NOT s.enabled`, targetID, jobID, result, failed, APIBASScheduleMaxFailures).Scan(&paused)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // the schedule was removed while the run was being queued
	}
	if err != nil {
		return false, fmt.Errorf("record apibas schedule result: %w", err)
	}
	return paused, nil
}
