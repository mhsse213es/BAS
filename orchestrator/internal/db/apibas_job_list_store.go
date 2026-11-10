package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// APIBASJobSummary is one job as a list shows it: what it was, how it ended, and how its scenarios graded. It carries no report body
// and no credential reference.
type APIBASJobSummary struct {
	ID            string
	RequestedBy   string
	Environment   string
	Fixture       string
	Status        string
	FailureReason string
	ScenarioCount int
	CreatedAt     time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
	Pass          int
	Fail          int
	Error         int
	Skipped       int
}

// MaxAPIBASJobList is the most jobs one list returns.
const MaxAPIBASJobList = 100

// ListAPIBASJobSummaries returns a target's jobs, newest first, with the count of each grade. limit is clamped to 1..MaxAPIBASJobList.
func ListAPIBASJobSummaries(ctx context.Context, pool *pgxpool.Pool, targetID string, limit int) ([]APIBASJobSummary, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > MaxAPIBASJobList {
		limit = MaxAPIBASJobList
	}
	rows, err := pool.Query(ctx, `
		SELECT j.id::text, j.requested_by, j.environment, j.fixture, j.status, j.failure_reason, jsonb_array_length(j.scenario_ids),
		       j.created_at, j.started_at, j.finished_at,
		       COUNT(r.*) FILTER (WHERE r.result = 'PASS'), COUNT(r.*) FILTER (WHERE r.result = 'FAIL'),
		       COUNT(r.*) FILTER (WHERE r.result = 'ERROR'), COUNT(r.*) FILTER (WHERE r.result = 'SKIPPED')
		  FROM apibas_jobs j
		  LEFT JOIN apibas_job_reports r ON r.job_id = j.id
		 WHERE j.target_id = $1
		 GROUP BY j.id
		 ORDER BY j.created_at DESC, j.id
		 LIMIT $2`, targetID, limit)
	if err != nil {
		return nil, fmt.Errorf("list apibas jobs: %w", err)
	}
	defer rows.Close()
	out := []APIBASJobSummary{}
	for rows.Next() {
		var s APIBASJobSummary
		if err := rows.Scan(&s.ID, &s.RequestedBy, &s.Environment, &s.Fixture, &s.Status, &s.FailureReason, &s.ScenarioCount,
			&s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.Pass, &s.Fail, &s.Error, &s.Skipped); err != nil {
			return nil, fmt.Errorf("read apibas job: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
