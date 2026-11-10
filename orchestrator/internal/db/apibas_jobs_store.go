package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIBASJob is one assessment job. Its status moves only forward: queued, then running, then completed, failed or cancelled.
type APIBASJob struct {
	ID            string
	JobKey        string
	TargetID      string
	RequestedBy   string
	TargetBaseURL string
	Environment   string
	Fixture       string
	ScenarioIDs   []string
	// CredentialRefs maps each runner secret name to its D4 secret-store reference. References are stored; values never are.
	CredentialRefs map[string]string
	// AllowedHosts are the registered hosts (host:port) the runner may reach besides loopback. Copied from the target at submit.
	AllowedHosts  []string
	// AllowedPaths are the registered path prefixes the runner may request. Copied from the target at submit. Empty means no path restriction (lab only).
	AllowedPaths []string
	Status        string
	FailureReason string
	CreatedAt     time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
}

// APIBASJobReport is the stored verdict for one scenario of a job. Report is the runner's JSON for that scenario.
type APIBASJobReport struct {
	ScenarioID     string
	RunTag         string
	Result         string
	Exploitability string
	Control        string
	Detection      string
	Reason         string
	Report         []byte
}

var (
	// ErrAPIBASJobNotFound means no job has the given id.
	ErrAPIBASJobNotFound = errors.New("apibas job not found")
	// ErrAPIBASJobState means the job is not in the status the operation requires.
	ErrAPIBASJobState = errors.New("apibas job is not in a valid state for this operation")
)

// CreateAPIBASJob stores a new job keyed by jobKey. A second call with the same key returns the existing job and created=false,
// so a retried request cannot create a second execution.
func CreateAPIBASJob(ctx context.Context, pool *pgxpool.Pool, j APIBASJob) (APIBASJob, bool, error) {
	scen, err := json.Marshal(j.ScenarioIDs)
	if err != nil {
		return APIBASJob{}, false, fmt.Errorf("encode scenario ids: %w", err)
	}
	hosts, _ := json.Marshal(j.AllowedHosts)
	paths, _ := json.Marshal(nonNil(j.AllowedPaths))
	refs, err := json.Marshal(j.CredentialRefs)
	if err != nil {
		return APIBASJob{}, false, fmt.Errorf("encode credential refs: %w", err)
	}
	var id string
	err = pool.QueryRow(ctx, `
		INSERT INTO apibas_jobs (job_key, requested_by, target_base_url, environment, fixture, scenario_ids, credential_refs, allowed_hosts, allowed_paths, status)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, 'queued')
		ON CONFLICT (job_key) DO NOTHING
		RETURNING id::text`,
		j.JobKey, j.RequestedBy, j.TargetBaseURL, j.Environment, j.Fixture, string(scen), string(refs), string(hosts), string(paths)).Scan(&id)
	if err == nil {
		got, gerr := GetAPIBASJob(ctx, pool, id)
		return got, true, gerr
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return APIBASJob{}, false, fmt.Errorf("create apibas job: %w", err)
	}
	existing, err := getAPIBASJobByKey(ctx, pool, j.JobKey)
	return existing, false, err
}

// StartAPIBASJob moves a queued job to running. It returns false if the job was already started or finished, which makes a
// repeated dispatch a no-op rather than a second execution.
func StartAPIBASJob(ctx context.Context, pool *pgxpool.Pool, id string) (bool, error) {
	tag, err := pool.Exec(ctx, `
		UPDATE apibas_jobs SET status = 'running', started_at = NOW()
		 WHERE id = $1::uuid AND status = 'queued'`, id)
	if err != nil {
		return false, fmt.Errorf("start apibas job: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// FinishAPIBASJob moves a running job to a terminal status. A completed job stores all its reports in the same transaction.
// A failed or cancelled job stores none. Both rules are enforced here as well as by the caller.
func FinishAPIBASJob(ctx context.Context, pool *pgxpool.Pool, id, status, reason string, reports []APIBASJobReport) error {
	switch status {
	case "completed":
		if len(reports) == 0 {
			return fmt.Errorf("%w: a completed job needs its reports", ErrAPIBASJobState)
		}
		if reason != "" {
			return fmt.Errorf("%w: a completed job carries no failure reason", ErrAPIBASJobState)
		}
	case "failed", "cancelled":
		if len(reports) != 0 {
			return fmt.Errorf("%w: a %s job must not store reports", ErrAPIBASJobState, status)
		}
		if reason == "" {
			return fmt.Errorf("%w: a %s job needs a reason", ErrAPIBASJobState, status)
		}
	default:
		return fmt.Errorf("%w: status %q is not terminal", ErrAPIBASJobState, status)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("finish apibas job: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	tag, err := tx.Exec(ctx, `
		UPDATE apibas_jobs SET status = $2, failure_reason = $3, finished_at = NOW()
		 WHERE id = $1::uuid AND status = 'running'`, id, status, reason)
	if err != nil {
		return fmt.Errorf("finish apibas job: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: job is not running", ErrAPIBASJobState)
	}
	for _, r := range reports {
		if !json.Valid(r.Report) {
			return fmt.Errorf("%w: report for %q is not valid JSON", ErrAPIBASJobState, r.ScenarioID)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO apibas_job_reports
				(job_id, scenario_id, run_tag, result, exploitability, control, detection, reason, report)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
			id, r.ScenarioID, r.RunTag, r.Result, r.Exploitability, r.Control, r.Detection, r.Reason, string(r.Report)); err != nil {
			return fmt.Errorf("store apibas job report: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// GetAPIBASJob returns one job by id.
func GetAPIBASJob(ctx context.Context, pool *pgxpool.Pool, id string) (APIBASJob, error) {
	return scanAPIBASJob(pool.QueryRow(ctx, apibasJobSelect+` WHERE id = $1::uuid`, id))
}

// FindAPIBASJobByKey returns the job with this idempotency key, if any.
func FindAPIBASJobByKey(ctx context.Context, pool *pgxpool.Pool, key string) (APIBASJob, bool, error) {
	j, err := getAPIBASJobByKey(ctx, pool, key)
	if errors.Is(err, ErrAPIBASJobNotFound) {
		return APIBASJob{}, false, nil
	}
	if err != nil {
		return APIBASJob{}, false, err
	}
	return j, true, nil
}

func getAPIBASJobByKey(ctx context.Context, pool *pgxpool.Pool, key string) (APIBASJob, error) {
	return scanAPIBASJob(pool.QueryRow(ctx, apibasJobSelect+` WHERE job_key = $1`, key))
}

// ListAPIBASJobReports returns the stored reports of one job in scenario order.
func ListAPIBASJobReports(ctx context.Context, pool *pgxpool.Pool, jobID string) ([]APIBASJobReport, error) {
	rows, err := pool.Query(ctx, `
		SELECT scenario_id, run_tag, result, exploitability, control, detection, reason, report::text
		  FROM apibas_job_reports WHERE job_id = $1::uuid ORDER BY scenario_id`, jobID)
	if err != nil {
		return nil, fmt.Errorf("list apibas job reports: %w", err)
	}
	defer rows.Close()
	var out []APIBASJobReport
	for rows.Next() {
		var r APIBASJobReport
		var raw string
		if err := rows.Scan(&r.ScenarioID, &r.RunTag, &r.Result, &r.Exploitability, &r.Control, &r.Detection, &r.Reason, &raw); err != nil {
			return nil, fmt.Errorf("scan apibas job report: %w", err)
		}
		r.Report = []byte(raw)
		out = append(out, r)
	}
	return out, rows.Err()
}

const apibasJobSelect = `SELECT id::text, job_key, target_id, requested_by, target_base_url, environment, fixture, scenario_ids::text,
	credential_refs::text, allowed_hosts::text, allowed_paths::text, status, failure_reason, created_at, started_at, finished_at FROM apibas_jobs`

// ReconcileStaleAPIBASJobs fails every job that has been running longer than olderThan. A crash of the orchestrator during a run
// leaves its job in 'running'; this makes that visible as a failure instead of a run that never ends. It returns the number of jobs
// it failed.
func ReconcileStaleAPIBASJobs(ctx context.Context, pool *pgxpool.Pool, olderThan time.Duration) (int64, error) {
	tag, err := pool.Exec(ctx, `
		UPDATE apibas_jobs SET status = 'failed', failure_reason = 'orchestrator stopped while the job was running', finished_at = NOW()
		 WHERE status = 'running' AND started_at < NOW() - make_interval(secs => $1)`, olderThan.Seconds())
	if err != nil {
		return 0, fmt.Errorf("reconcile apibas jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanAPIBASJob(row pgx.Row) (APIBASJob, error) {
	var j APIBASJob
	var scen, refs, hosts, paths string
	err := row.Scan(&j.ID, &j.JobKey, &j.TargetID, &j.RequestedBy, &j.TargetBaseURL, &j.Environment, &j.Fixture, &scen, &refs, &hosts, &paths,
		&j.Status, &j.FailureReason, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIBASJob{}, ErrAPIBASJobNotFound
	}
	if err != nil {
		return APIBASJob{}, fmt.Errorf("read apibas job: %w", err)
	}
	if err := json.Unmarshal([]byte(scen), &j.ScenarioIDs); err != nil {
		return APIBASJob{}, fmt.Errorf("decode scenario ids: %w", err)
	}
	if err := json.Unmarshal([]byte(hosts), &j.AllowedHosts); err != nil {
		return APIBASJob{}, fmt.Errorf("decode allowed hosts: %w", err)
	}
	if err := json.Unmarshal([]byte(paths), &j.AllowedPaths); err != nil {
		return APIBASJob{}, fmt.Errorf("decode allowed paths: %w", err)
	}
	if err := json.Unmarshal([]byte(refs), &j.CredentialRefs); err != nil {
		return APIBASJob{}, fmt.Errorf("decode credential refs: %w", err)
	}
	return j, nil
}
