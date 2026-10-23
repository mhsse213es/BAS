package store

import (
	"context"
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
