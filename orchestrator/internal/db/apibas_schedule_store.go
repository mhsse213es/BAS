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
	TargetID            string
	EveryHours          int
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

const apibasScheduleColumns = `target_id, every_hours, include_writes, enabled, next_run_at, created_by, created_at, updated_at, last_run_at, last_job_id, last_result, consecutive_failures`

func scanAPIBASSchedule(row pgx.Row, extra ...any) (APIBASSchedule, error) {
	var s APIBASSchedule
	dest := append([]any{&s.TargetID, &s.EveryHours, &s.IncludeWrites, &s.Enabled, &s.NextRunAt, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
		&s.LastRunAt, &s.LastJobID, &s.LastResult, &s.ConsecutiveFailures}, extra...)
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
		INSERT INTO apibas_schedules (target_id, every_hours, include_writes, enabled, next_run_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (target_id) DO UPDATE
		   SET every_hours = EXCLUDED.every_hours, include_writes = EXCLUDED.include_writes, enabled = EXCLUDED.enabled,
		       next_run_at = EXCLUDED.next_run_at, created_by = EXCLUDED.created_by, updated_at = NOW(), consecutive_failures = 0
		RETURNING `+apibasScheduleColumns, rec.TargetID, rec.EveryHours, rec.IncludeWrites, rec.Enabled, rec.NextRunAt, rec.CreatedBy))
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
	rows, err := pool.Query(ctx, `
		WITH due AS (
			SELECT target_id, next_run_at AS due_at FROM apibas_schedules
			 WHERE enabled AND next_run_at <= $1 ORDER BY next_run_at LIMIT $2 FOR UPDATE SKIP LOCKED)
		UPDATE apibas_schedules s
		   SET next_run_at = $1 + make_interval(hours => s.every_hours), last_run_at = $1
		  FROM due
		 WHERE s.target_id = due.target_id
		RETURNING s.target_id, s.every_hours, s.include_writes, s.enabled, s.next_run_at, s.created_by, s.created_at, s.updated_at,
		          s.last_run_at, s.last_job_id, s.last_result, s.consecutive_failures, due.due_at`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("claim apibas schedules: %w", err)
	}
	defer rows.Close()
	var out []APIBASSchedule
	for rows.Next() {
		var due time.Time
		s, err := scanAPIBASSchedule(rows, &due)
		if err != nil {
			return nil, fmt.Errorf("scan apibas schedule: %w", err)
		}
		s.DueAt = due
		out = append(out, s)
	}
	return out, rows.Err()
}

// RecordAPIBASScheduleResult stores what a scheduled run did. A failure to queue the job counts toward pausing the schedule, which
// pauses itself at APIBASScheduleMaxFailures in a row so a broken schedule does not retry for ever. A success resets the count.
func RecordAPIBASScheduleResult(ctx context.Context, pool *pgxpool.Pool, targetID, jobID, result string, failed bool) error {
	_, err := pool.Exec(ctx, `
		UPDATE apibas_schedules
		   SET last_job_id = $2, last_result = $3,
		       consecutive_failures = CASE WHEN $4 THEN consecutive_failures + 1 ELSE 0 END,
		       enabled = CASE WHEN $4 AND consecutive_failures + 1 >= $5 THEN false ELSE enabled END
		 WHERE target_id = $1`, targetID, jobID, result, failed, APIBASScheduleMaxFailures)
	if err != nil {
		return fmt.Errorf("record apibas schedule result: %w", err)
	}
	return nil
}
