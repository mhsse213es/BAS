package store

import (
	"context"
	"fmt"
	"time"
)

// GetRun loads a run's engagement id (empty when none) and creation time. A missing run
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func (s *Store) GetRun(ctx context.Context, id string) (engagementID string, createdAt time.Time, err error) {
	var eng *string
	err = s.pool.QueryRow(ctx, `SELECT engagement_id, created_at FROM aleef_runs WHERE id=$1`, id).Scan(&eng, &createdAt)
	if eng != nil {
		engagementID = *eng
	}
	return engagementID, createdAt, err
}

// ListFindingsBy lists findings that are not verified, newest first, grouped by state:
// candidates, and everything else (rejected, unconfirmed). runID "" means all runs. Verified
// findings are deliberately not returned: present them through ListVerifiedWithRegression, so a
// verified finding without a saved regression is never shown as verified. A state that is
// verified in the database is omitted here whether or not it has a regression.
func (s *Store) ListFindingsBy(ctx context.Context, runID string) (candidates, others []Finding, err error) {
	q := `SELECT ` + findingCols + ` FROM aleef_findings WHERE state <> 'verified'`
	var args []any
	if runID != "" {
		q += ` AND run_id=$1`
		args = append(args, runID)
	}
	rows, err := s.pool.Query(ctx, q+` ORDER BY created_at DESC, id LIMIT 1000`, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, nil, err
		}
		if f.State == StateCandidate {
			candidates = append(candidates, f)
		} else {
			others = append(others, f)
		}
	}
	return candidates, others, rows.Err()
}

// ListUnregressedVerified returns verified findings that have no saved regression, with no
// grace period (runID "" means all runs). The API reports these as pending, never as verified.
func (s *Store) ListUnregressedVerified(ctx context.Context, runID string) ([]Finding, error) {
	return s.listVerified(ctx, runID, `NOT EXISTS (SELECT 1 FROM aleef_regressions r WHERE r.finding_id=f.id)`)
}

// Run statuses.
const (
	RunRunning     = "running"
	RunCompleted   = "completed"
	RunHalted      = "halted"
	RunFailed      = "failed"
	RunInterrupted = "interrupted"
)

// RunRecord is the persisted outcome of a run.
type RunRecord struct {
	ID, EngagementID, Status, HaltedReason string
	CreatedAt                              time.Time
	FinishedAt                             *time.Time
	Report, Orphans                        []byte // JSON; Report is nil until the run ends
}

// MarkRunFinished records the final outcome of a run still marked running. report and orphans
// must be JSON (nil report stores NULL, nil orphans stores []). It never overwrites a run that
// was already finished or marked interrupted.
func (s *Store) MarkRunFinished(ctx context.Context, id, status, haltedReason string, report, orphans []byte) error {
	switch status {
	case RunCompleted, RunHalted, RunFailed, RunInterrupted:
	default:
		return fmt.Errorf("aleef store: invalid final run status %q", status)
	}
	if len(orphans) == 0 {
		orphans = []byte(`[]`)
	}
	var rep any
	if len(report) > 0 {
		rep = string(report)
	}
	_, err := s.pool.Exec(ctx, `UPDATE aleef_runs SET status=$2, halted_reason=$3, report=$4::jsonb, orphans=$5::jsonb, finished_at=NOW()
		WHERE id=$1 AND status='running'`, id, status, haltedReason, rep, string(orphans))
	return err
}

// MarkRunsInterrupted marks every run still 'running' as 'interrupted' (the process that was
// running them is gone) and returns their ids. It is global and assumes a single orchestrator instance
// per database (the documented on-prem model). Call it once at server start, before runs can be
// started.
func (s *Store) MarkRunsInterrupted(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `UPDATE aleef_runs SET status='interrupted', finished_at=NOW(),
		halted_reason='server stopped before the campaign finished; objects created on the target may remain'
		WHERE status='running' RETURNING id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetRunRecord loads a run with its persisted outcome. A missing run returns an error
// satisfying errors.Is(err, pgx.ErrNoRows).
func (s *Store) GetRunRecord(ctx context.Context, id string) (RunRecord, error) {
	var r RunRecord
	var eng *string
	var rep, orph *string
	err := s.pool.QueryRow(ctx, `SELECT id, engagement_id, status, halted_reason, created_at, finished_at, report::text, orphans::text
		FROM aleef_runs WHERE id=$1`, id).Scan(&r.ID, &eng, &r.Status, &r.HaltedReason, &r.CreatedAt, &r.FinishedAt, &rep, &orph)
	if err != nil {
		return RunRecord{}, err
	}
	if eng != nil {
		r.EngagementID = *eng
	}
	if rep != nil {
		r.Report = []byte(*rep)
	}
	if orph != nil {
		r.Orphans = []byte(*orph)
	}
	return r, nil
}
