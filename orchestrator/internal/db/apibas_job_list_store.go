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

// APIBASJobListOptions narrows and pages a job list. Zero values mean no filter and the first page.
type APIBASJobListOptions struct {
	Limit  int    // clamped to 1..MaxAPIBASJobList
	Status string // one of queued, running, completed, failed, cancelled; empty for all
	// BeforeAt and BeforeID continue after the last job of the previous page (its creation time and id). Both are set, or neither.
	BeforeAt *time.Time
	BeforeID string
}

// ValidAPIBASJobStatus reports whether s is a job status a list can filter on.
func ValidAPIBASJobStatus(s string) bool {
	switch s {
	case "queued", "running", "completed", "failed", "cancelled":
		return true
	}
	return false
}

// ListAPIBASJobSummaries returns a target's jobs, newest first, with the count of each grade. It asks for one more row than the page
// holds and reports whether that row existed, so a caller knows if another page follows without a second query.
func ListAPIBASJobSummaries(ctx context.Context, pool *pgxpool.Pool, targetID string, opts APIBASJobListOptions) (jobs []APIBASJobSummary, more bool, err error) {
	limit := opts.Limit
	if limit < 1 {
		limit = 1
	}
	if limit > MaxAPIBASJobList {
		limit = MaxAPIBASJobList
	}
	if opts.Status != "" && !ValidAPIBASJobStatus(opts.Status) {
		return nil, false, fmt.Errorf("list apibas jobs: unknown status %q", opts.Status)
	}
	if (opts.BeforeAt == nil) != (opts.BeforeID == "") {
		return nil, false, fmt.Errorf("list apibas jobs: a continuation needs both a time and an id")
	}
	var beforeAt any
	if opts.BeforeAt != nil {
		beforeAt = *opts.BeforeAt
	}
	rows, err := pool.Query(ctx, `
		SELECT j.id::text, j.requested_by, j.environment, j.fixture, j.status, j.failure_reason, jsonb_array_length(j.scenario_ids),
		       j.created_at, j.started_at, j.finished_at,
		       COUNT(r.*) FILTER (WHERE r.result = 'PASS'), COUNT(r.*) FILTER (WHERE r.result = 'FAIL'),
		       COUNT(r.*) FILTER (WHERE r.result = 'ERROR'), COUNT(r.*) FILTER (WHERE r.result = 'SKIPPED')
		  FROM apibas_jobs j
		  LEFT JOIN apibas_job_reports r ON r.job_id = j.id
		 WHERE j.target_id = $1
		   AND ($2 = '' OR j.status = $2)
		   AND ($3::timestamptz IS NULL OR (j.created_at, j.id::text) < ($3::timestamptz, $4))
		 GROUP BY j.id
		 ORDER BY j.created_at DESC, j.id::text DESC
		 LIMIT $5`, targetID, opts.Status, beforeAt, opts.BeforeID, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list apibas jobs: %w", err)
	}
	defer rows.Close()
	out := []APIBASJobSummary{}
	for rows.Next() {
		var s APIBASJobSummary
		if err := rows.Scan(&s.ID, &s.RequestedBy, &s.Environment, &s.Fixture, &s.Status, &s.FailureReason, &s.ScenarioCount,
			&s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.Pass, &s.Fail, &s.Error, &s.Skipped); err != nil {
			return nil, false, fmt.Errorf("read apibas job: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}
