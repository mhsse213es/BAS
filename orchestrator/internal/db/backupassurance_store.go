package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/backupassurance"
	"github.com/audspect/bas/internal/controlval"
)

// ErrAssessmentNotFound: the given assessmentID was never written (0 rows).
var ErrAssessmentNotFound = errors.New("backup assurance assessment not found")

// ErrAssessmentIncomplete: 1-5 rows exist for the assessmentID, never 6 --
// this should be unreachable given WriteBackupAssuranceAssessment's atomic
// write, so it signals a data-integrity problem (direct tampering, a bug
// elsewhere), not a normal "not found" case. A reader must surface this,
// never silently return the partial subset as if it were complete.
var ErrAssessmentIncomplete = errors.New("backup assurance assessment has an incomplete row count")

// WriteBackupAssuranceAssessment validates every result's Verdict/SkipReason
// pairing before opening a transaction (same discipline as
// WriteRWCapabilityResults), then mints one fresh assessment_id via
// Postgres's own gen_random_uuid() (the same mechanism rw_capability_results.id
// already uses) and inserts all 6 rows under that one shared ID inside a
// single transaction -- a failure on any row rolls back every row, so a
// failed write never leaves a partial assessment that looks complete.
func WriteBackupAssuranceAssessment(ctx context.Context, pool *pgxpool.Pool, results []backupassurance.CheckResult) (string, error) {
	for _, r := range results {
		if err := r.Valid(); err != nil {
			return "", fmt.Errorf("backup_assurance_results: refusing to write invalid result for %s: %w", r.Check, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("backup_assurance_results: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var assessmentID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&assessmentID); err != nil {
		return "", fmt.Errorf("backup_assurance_results: mint assessment id: %w", err)
	}

	for _, r := range results {
		var skipReason *string
		if r.SkipReason != "" {
			s := string(r.SkipReason)
			skipReason = &s
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO backup_assurance_results
				(assessment_id, check_name, verdict, skip_reason, reason, simulated, observer)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			assessmentID, string(r.Check), string(r.Verdict), skipReason, r.Reason, r.Simulated, r.Observer)
		if err != nil {
			return "", fmt.Errorf("backup_assurance_results: write failed for check=%s: %w", r.Check, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("backup_assurance_results: commit: %w", err)
	}
	return assessmentID, nil
}

// ReadBackupAssuranceAssessment fetches every row for assessmentID and
// explicitly checks the count: 0 rows is ErrAssessmentNotFound, 1-5 rows
// is ErrAssessmentIncomplete (a data-integrity failure, never silently
// returned as a shorter-than-expected success), 6 rows is success.
func ReadBackupAssuranceAssessment(ctx context.Context, pool *pgxpool.Pool, assessmentID string) ([]backupassurance.CheckResult, error) {
	rows, err := pool.Query(ctx, `
		SELECT check_name, verdict, COALESCE(skip_reason, ''), reason, simulated, observer
		  FROM backup_assurance_results
		 WHERE assessment_id = $1`, assessmentID)
	if err != nil {
		return nil, fmt.Errorf("backup_assurance_results: query failed for assessment=%s: %w", assessmentID, err)
	}
	defer rows.Close()

	var out []backupassurance.CheckResult
	for rows.Next() {
		var checkName, verdict, skipReason, reason, observer string
		var sim bool
		if err := rows.Scan(&checkName, &verdict, &skipReason, &reason, &sim, &observer); err != nil {
			return nil, fmt.Errorf("backup_assurance_results: scan failed for assessment=%s: %w", assessmentID, err)
		}
		out = append(out, backupassurance.CheckResult{
			Check: backupassurance.Check(checkName), Verdict: controlval.Verdict(verdict), SkipReason: controlval.SkipReason(skipReason),
			Reason: reason, Simulated: sim, Observer: observer,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backup_assurance_results: row iteration failed for assessment=%s: %w", assessmentID, err)
	}
	switch len(out) {
	case 0:
		return nil, fmt.Errorf("%w: assessment_id=%s", ErrAssessmentNotFound, assessmentID)
	case 6:
		return out, nil
	default:
		return nil, fmt.Errorf("%w: assessment_id=%s has %d of 6 expected rows", ErrAssessmentIncomplete, assessmentID, len(out))
	}
}
