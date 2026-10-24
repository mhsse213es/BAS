package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

// EnsureDBSimJobSchema creates dbsim_run_jobs and its partial unique indexes
// (idempotent; CREATE ... IF NOT EXISTS only). The DDL lives in internal/dbsim
// so its shape is testable without Docker.
func EnsureDBSimJobSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, s := range dbsim.JobsSchemaSQL {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("dbsim_run_jobs: ensure schema: %w", err)
		}
	}
	return nil
}

// DBSimJobStore is the Postgres-backed job store (it satisfies dbjobs.JobStore
// structurally; this package cannot import dbjobs). Every mutation writes its
// audit row in the same transaction through withDBSimAuditTx. The plan holds
// credential REFERENCES only.
type DBSimJobStore struct{ Pool *pgxpool.Pool }

const dbsimJobCols = `id, kind, target_id, agent_id, mode, scenario_ids, plan, status, reason, created_by,
	lab_confirmation, created_at, started_at, deadline`

func scanDBSimJob(row pgx.Row) (dbsim.RunJob, error) {
	var (
		j                  dbsim.RunJob
		kind, mode, status string
		scenarioIDs, plan  []byte
		startedAt          *time.Time
	)
	if err := row.Scan(&j.ID, &kind, &j.TargetID, &j.AgentID, &mode, &scenarioIDs, &plan, &status, &j.Reason,
		&j.CreatedBy, &j.LabConfirmation, &j.CreatedAt, &startedAt, &j.Deadline); err != nil {
		return dbsim.RunJob{}, err
	}
	j.Kind, j.Mode, j.Status = dbsim.JobKind(kind), dbsim.ExecMode(mode), dbsim.JobStatus(status)
	if startedAt != nil {
		j.StartedAt = *startedAt
	}
	if len(scenarioIDs) > 0 {
		if err := json.Unmarshal(scenarioIDs, &j.ScenarioIDs); err != nil {
			return dbsim.RunJob{}, fmt.Errorf("scenario_ids: %w", err)
		}
	}
	if len(plan) > 0 {
		if err := json.Unmarshal(plan, &j.Plan); err != nil {
			return dbsim.RunJob{}, fmt.Errorf("plan: %w", err)
		}
	}
	return j, nil
}

// Create stores a new pending job with its audit row. dbsim.ErrJobBusy when the
// partial unique index refuses a second active job for the same target or agent.
func (s DBSimJobStore) Create(ctx context.Context, j dbsim.RunJob, audit dbadmin.AuditEntry) error {
	if j.Status != dbsim.JobPending {
		return fmt.Errorf("create dbsim job: new jobs start pending, got %q", j.Status)
	}
	ids := j.ScenarioIDs
	if ids == nil {
		ids = []string{}
	}
	plan := j.Plan
	if plan == nil {
		plan = []dbsim.PlannedStep{}
	}
	idb, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("create dbsim job: %w", err)
	}
	pb, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("create dbsim job: %w", err)
	}
	kind := j.Kind
	if kind == "" {
		kind = dbsim.JobKindRun
	}
	err = withDBSimAuditTx(ctx, s.Pool, audit, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO dbsim_run_jobs (id, kind, target_id, agent_id, mode, scenario_ids, plan, status, reason,
				created_by, lab_confirmation, created_at, deadline)
			VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9,$10,$11,$12,$13)`,
			j.ID, string(kind), j.TargetID, j.AgentID, string(j.Mode), string(idb), string(pb), string(j.Status), j.Reason,
			j.CreatedBy, j.LabConfirmation, j.CreatedAt, j.Deadline)
		return err
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.HasPrefix(pgErr.ConstraintName, "dbsim_run_jobs_one_active") {
			return dbsim.ErrJobBusy
		}
		return fmt.Errorf("create dbsim job: %w", err)
	}
	return nil
}

// Get returns one job; dbsim.ErrJobNotFound when absent.
func (s DBSimJobStore) Get(ctx context.Context, id string) (dbsim.RunJob, error) {
	j, err := scanDBSimJob(s.Pool.QueryRow(ctx, `SELECT `+dbsimJobCols+` FROM dbsim_run_jobs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return dbsim.RunJob{}, dbsim.ErrJobNotFound
	}
	if err != nil {
		return dbsim.RunJob{}, fmt.Errorf("get dbsim job: %w", err)
	}
	return j, nil
}

var errDBSimJobNoChange = errors.New("dbsim job: no row changed")

// Transition moves the job to `to` only if its status is one of `from`, in ONE
// guarded UPDATE, and reports whether a row changed. Only moves the job state
// machine allows are applied (`from` is narrowed to the states that may reach
// `to`); the audit row is written in the same transaction and only when the
// row changed.
func (s DBSimJobStore) Transition(ctx context.Context, id string, from []dbsim.JobStatus, to dbsim.JobStatus, reason string, audit dbadmin.AuditEntry) (bool, error) {
	if !to.Valid() {
		return false, fmt.Errorf("transition dbsim job: invalid status %q", to)
	}
	legal := make([]string, 0, len(from))
	for _, f := range from {
		if f.CanTransitionTo(to) {
			legal = append(legal, string(f))
		}
	}
	if len(legal) == 0 {
		return false, fmt.Errorf("transition dbsim job: no listed state may move to %q", to)
	}
	err := withDBSimAuditTx(ctx, s.Pool, audit, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE dbsim_run_jobs
			SET status = $2::text, reason = $3,
			    started_at = CASE WHEN $2::text = 'running' THEN NOW() ELSE started_at END,
			    updated_at = NOW()
			WHERE id = $1 AND status = ANY($4::text[])`,
			id, string(to), reason, legal)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errDBSimJobNoChange // rolls back, so no audit row for a no-op
		}
		return nil
	})
	if errors.Is(err, errDBSimJobNoChange) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("transition dbsim job: %w", err)
	}
	return true, nil
}

// ActiveForTarget reports whether the target has a pending or running job.
func (s DBSimJobStore) ActiveForTarget(ctx context.Context, targetID string) (bool, error) {
	var ok bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM dbsim_run_jobs WHERE target_id = $1 AND status IN ('pending','running'))`,
		targetID).Scan(&ok); err != nil {
		return false, fmt.Errorf("dbsim active job for target: %w", err)
	}
	return ok, nil
}

// ActiveForAgent reports whether the agent has a pending or running job.
func (s DBSimJobStore) ActiveForAgent(ctx context.Context, agentID string) (bool, error) {
	var ok bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM dbsim_run_jobs WHERE agent_id = $1 AND status IN ('pending','running'))`,
		agentID).Scan(&ok); err != nil {
		return false, fmt.Errorf("dbsim active job for agent: %w", err)
	}
	return ok, nil
}

// Expired lists active jobs whose deadline is before now (oldest first).
func (s DBSimJobStore) Expired(ctx context.Context, now time.Time) ([]dbsim.RunJob, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+dbsimJobCols+` FROM dbsim_run_jobs
		WHERE status IN ('pending','running') AND deadline < $1 ORDER BY deadline`, now)
	if err != nil {
		return nil, fmt.Errorf("dbsim expired jobs: %w", err)
	}
	defer rows.Close()
	var out []dbsim.RunJob
	for rows.Next() {
		j, err := scanDBSimJob(rows)
		if err != nil {
			return nil, fmt.Errorf("dbsim expired jobs: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
