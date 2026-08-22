package jobs

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// CreateBatch creates a Job plus one JobTarget per agentID, dispatching
// immediately (ScheduledAt=nil). Delegates to CreateBatchScheduled so
// every existing call site's behavior is unchanged.
func (s *Store) CreateBatch(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string) (Job, error) {
	return s.CreateBatchScheduled(ctx, jobType, payload, createdBy, agentIDs, nil)
}

// CreateBatchScheduled is CreateBatch with an optional future dispatch time.
func (s *Store) CreateBatchScheduled(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string, scheduledAt *time.Time) (Job, error) {
	return s.CreateBatchWithConcurrency(ctx, jobType, payload, createdBy, agentIDs, scheduledAt, 0)
}

// CreateBatchWithConcurrency is CreateBatchScheduled plus an optional
// per-job concurrency limit (0 = unlimited), read by Dispatcher.Tick's
// pending-dispatch loop to throttle how many of this job's targets run
// simultaneously. A single transaction so a job never exists with a
// partial target list.
func (s *Store) CreateBatchWithConcurrency(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string, scheduledAt *time.Time, concurrencyLimit int) (Job, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback(ctx)

	var jobID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO jobs (type, state, payload, created_by, scheduled_at, concurrency_limit) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		jobType, JobStateRequested, []byte(payload), createdBy, scheduledAt, concurrencyLimit,
	).Scan(&jobID); err != nil {
		return Job{}, err
	}
	for _, agentID := range agentIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO job_targets (job_id, agent_id, state) VALUES ($1,$2,$3)`,
			jobID, agentID, TargetStatePending,
		); err != nil {
			return Job{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Job{}, err
	}
	return s.Get(ctx, jobID)
}

func (s *Store) Get(ctx context.Context, id string) (Job, error) {
	var j Job
	err := s.pool.QueryRow(ctx,
		`SELECT id, type, state, payload, created_by, created_at, started_at, completed_at, scheduled_at, concurrency_limit, initiative_id FROM jobs WHERE id=$1`, id,
	).Scan(&j.ID, &j.Type, &j.State, &j.Payload, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &j.ScheduledAt, &j.ConcurrencyLimit, &j.InitiativeID)
	return j, err
}

// SetJobInitiative assigns, reassigns, or clears (initiativeID == "") a
// Job's initiative membership. Pure plumbing -- no rule about the target
// initiative's lifecycle state lives here; internal/api enforces "only an
// active initiative accepts new members" before calling this.
func (s *Store) SetJobInitiative(ctx context.Context, jobID, initiativeID string) (Job, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE jobs SET initiative_id=$1 WHERE id=$2`, initiativeID, jobID); err != nil {
		return Job{}, err
	}
	return s.Get(ctx, jobID)
}

func scanJobTargets(rows pgx.Rows) ([]JobTarget, error) {
	defer rows.Close()
	var out []JobTarget
	for rows.Next() {
		var t JobTarget
		if err := rows.Scan(&t.ID, &t.JobID, &t.AgentID, &t.State, &t.RefID, &t.Error,
			&t.RetryCount, &t.MaxRetries, &t.CreatedAt, &t.StartedAt, &t.CompletedAt,
			&t.OwnerID, &t.AssignedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

const jobTargetColumns = `id, job_id, agent_id, state, ref_id, error, retry_count, max_retries, created_at, started_at, completed_at, owner_id, assigned_at`

func (s *Store) ListTargets(ctx context.Context, jobID string) ([]JobTarget, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobTargetColumns+` FROM job_targets WHERE job_id=$1 ORDER BY created_at`, jobID)
	if err != nil {
		return nil, err
	}
	return scanJobTargets(rows)
}

// ListActiveDispatchedTargets returns every in-flight target across every
// job that is not yet in a terminal or cancelled state.
func (s *Store) ListActiveDispatchedTargets(ctx context.Context) ([]JobTarget, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobTargetColumnsQualified()+`
		   FROM job_targets jt JOIN jobs j ON j.id = jt.job_id
		  WHERE jt.state = $1 AND j.state IN ($2,$3)`,
		TargetStateDispatched, JobStateRequested, JobStateRunning)
	if err != nil {
		return nil, err
	}
	return scanJobTargets(rows)
}

// ListPendingTargetsAcrossActiveJobs returns up to limit still-pending
// targets across every active job, oldest first -- the set Tick() dispatches
// on a given tick.
func (s *Store) ListPendingTargetsAcrossActiveJobs(ctx context.Context, limit int) ([]JobTarget, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobTargetColumnsQualified()+`
		   FROM job_targets jt JOIN jobs j ON j.id = jt.job_id
		  WHERE jt.state = $1 AND j.state IN ($2,$3)
		    AND (j.scheduled_at IS NULL OR j.scheduled_at <= NOW())
		  ORDER BY jt.created_at, jt.id
		  LIMIT $4`,
		TargetStatePending, JobStateRequested, JobStateRunning, limit)
	if err != nil {
		return nil, err
	}
	return scanJobTargets(rows)
}

// jobTargetColumnsQualified is jobTargetColumns with every column prefixed
// "jt." for use in the JOINed queries above -- jobs (aliased "j") has its
// own id/state/created_at/started_at/completed_at columns, so an unqualified
// SELECT against the join would fail with "column reference is ambiguous".
func jobTargetColumnsQualified() string {
	return `jt.id, jt.job_id, jt.agent_id, jt.state, jt.ref_id, jt.error, jt.retry_count, jt.max_retries, jt.created_at, jt.started_at, jt.completed_at, jt.owner_id, jt.assigned_at`
}

func (s *Store) MarkTargetDispatched(ctx context.Context, targetID, refID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE job_targets SET state=$1, ref_id=$2, started_at=NOW() WHERE id=$3`,
		TargetStateDispatched, refID, targetID)
	return err
}

func (s *Store) MarkTargetTerminal(ctx context.Context, targetID, state, errText string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE job_targets SET state=$1, error=$2, completed_at=NOW() WHERE id=$3`,
		state, errText, targetID)
	return err
}

func (s *Store) ListDeferredTargets(ctx context.Context) ([]JobTarget, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobTargetColumnsQualified()+`
		   FROM job_targets jt JOIN jobs j ON j.id = jt.job_id
		  WHERE jt.state = $1 AND j.state IN ($2,$3)`,
		TargetStateDeferred, JobStateRequested, JobStateRunning)
	if err != nil {
		return nil, err
	}
	return scanJobTargets(rows)
}

func (s *Store) MarkTargetDeferred(ctx context.Context, targetID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE job_targets SET state=$1, error=$2 WHERE id=$3`,
		TargetStateDeferred, reason, targetID)
	return err
}

func (s *Store) MarkTargetPending(ctx context.Context, targetID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE job_targets SET state=$1, error='' WHERE id=$2`,
		TargetStatePending, targetID)
	return err
}

// SetTargetOwner assigns or clears a JobTarget's owner. ownerID == ""
// clears ownership and nulls assigned_at back out. Returns pgx.ErrNoRows
// if targetID doesn't exist.
func (s *Store) SetTargetOwner(ctx context.Context, targetID, ownerID string) (JobTarget, error) {
	var t JobTarget
	err := s.pool.QueryRow(ctx,
		`UPDATE job_targets SET owner_id=$1, assigned_at = CASE WHEN $1 = '' THEN NULL ELSE NOW() END
		 WHERE id=$2
		 RETURNING `+jobTargetColumns,
		ownerID, targetID,
	).Scan(&t.ID, &t.JobID, &t.AgentID, &t.State, &t.RefID, &t.Error, &t.RetryCount, &t.MaxRetries,
		&t.CreatedAt, &t.StartedAt, &t.CompletedAt, &t.OwnerID, &t.AssignedAt)
	return t, err
}

// ListTargetsByOwner returns every JobTarget currently assigned to
// ownerID, across every job, most-recently-assigned first. state, if
// non-empty, narrows to that TargetState value -- the first query in this
// codebase that lists JobTarget rows across every job rather than one.
func (s *Store) ListTargetsByOwner(ctx context.Context, ownerID, state string) ([]JobTarget, error) {
	if state == "" {
		rows, err := s.pool.Query(ctx,
			`SELECT `+jobTargetColumns+` FROM job_targets WHERE owner_id=$1 ORDER BY assigned_at DESC`, ownerID)
		if err != nil {
			return nil, err
		}
		return scanJobTargets(rows)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobTargetColumns+` FROM job_targets WHERE owner_id=$1 AND state=$2 ORDER BY assigned_at DESC`,
		ownerID, state)
	if err != nil {
		return nil, err
	}
	return scanJobTargets(rows)
}

// SetJobState persists a Job's aggregate state. StartedAt is stamped the
// first time state moves off "requested" (COALESCE keeps any existing
// value); CompletedAt is stamped whenever state lands in a terminal value.
func (s *Store) SetJobState(ctx context.Context, jobID, state string) error {
	if IsTerminalJobState(state) {
		_, err := s.pool.Exec(ctx,
			`UPDATE jobs SET state=$1, started_at=COALESCE(started_at, NOW()), completed_at=NOW() WHERE id=$2`,
			state, jobID)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE jobs SET state=$1, started_at=COALESCE(started_at, NOW()) WHERE id=$2`,
		state, jobID)
	return err
}

// CancelJob cancels every still-pending target for jobID and marks the job
// itself cancelled. Targets already dispatched are left untouched -- that
// WS message already went out; an operator cancels an in-flight target
// individually via Sub-project 4's existing per-remediation cancel endpoint.
func (s *Store) CancelJob(ctx context.Context, jobID string) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE job_targets SET state=$1, completed_at=NOW() WHERE job_id=$2 AND state=$3`,
		TargetStateCancelled, jobID, TargetStatePending)
	if err != nil {
		return 0, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE jobs SET state=$1, completed_at=NOW() WHERE id=$2`,
		JobStateCancelled, jobID,
	); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
