# Fleet Job Engine (Sub-project 6, Phases 1+2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a generic, persisted `Job`/`JobTarget` engine (`internal/jobs`) and prove it with one real consumer — batch remediation, fanning an existing single-endpoint remediation out to N agents with independently tracked, cancellable, resumable progress.

**Architecture:** New sibling package `internal/jobs` (types + Postgres-backed store + a `Tick()`-driven dispatch loop), mirroring `internal/vexsweep`'s proven shape (persisted progress, advance-by-one-step-per-tick, `exercise.PollScheduler`-driven, dependency-injected dispatch to avoid an import cycle back into `internal/api`). `internal/jobs` never imports `internal/remediation` or `internal/api` — it knows nothing about what a "batch_remediation" job actually does. `internal/api` supplies the one dispatch/status function pair this cycle needs, and every batch target's execution reuses Sub-project 4's exact `remediation_requests` pipeline (`dispatchRemediationStep`) — the Job Engine never reimplements remediation dispatch, it only polls `remediation_requests.status` per target.

**Tech Stack:** Go, PostgreSQL (`pgx/v5`), `chi` router, existing `exercise.PollScheduler` ticker primitive.

## Global Constraints

- Direct-to-`main` repo convention — no branches/PRs; every task commits and pushes straight to `main`.
- TDD throughout: write failing test → verify it fails → implement → verify it passes → commit → push.
- `internal/jobs` is purely additive. Sub-project 4's `internal/remediation`, `remediation_requests` table, `ExecuteRemediation` handler, and its continuation hooks (`remediation_continuation.go`) are never modified.
- Batch remediation reuses Sub-project 4's existing tier-based permissions (`auth.CanExecuteRemediation` for Tier 1, `auth.CanApproveRemediation` for Tier 2) — no new permission is created.
- `jobDispatchBatchSize = 20` caps how many targets `Tick()` dispatches per call, mirroring `revalidationBatchSize = 10`'s reasoning in `internal/api/revalidation.go`.
- `jobsScheduler := exercise.NewPollScheduler(5 * time.Second)` — same interval as `vexSweepScheduler`/`exScheduler` in `main.go`.
- Every DB-backed test in this codebase follows the `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` pattern and starts with `if testing.Short() { t.Skip(...) }`.

---

### Task 1: `internal/jobs` types + pure state-aggregation logic

**Files:**
- Create: `orchestrator/internal/jobs/types.go`
- Create: `orchestrator/internal/jobs/state.go`
- Test: `orchestrator/internal/jobs/state_test.go`

**Interfaces:**
- Produces: `Job` struct, `JobTarget` struct, `JobState*`/`TargetState*` string constants, `AggregateState(current string, targets []JobTarget) string` — every later task in this plan imports these from `internal/jobs`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/jobs/state_test.go
package jobs

import "testing"

func TestAggregateState_AllPendingStaysRequested(t *testing.T) {
	targets := []JobTarget{{State: TargetStatePending}, {State: TargetStatePending}}
	got := AggregateState(JobStateRequested, targets)
	if got != JobStateRequested {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateRequested)
	}
}

func TestAggregateState_SomeDispatchedBecomesRunning(t *testing.T) {
	targets := []JobTarget{{State: TargetStateDispatched}, {State: TargetStatePending}}
	got := AggregateState(JobStateRequested, targets)
	if got != JobStateRunning {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateRunning)
	}
}

func TestAggregateState_AllCompletedBecomesCompleted(t *testing.T) {
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateCompleted}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStateCompleted {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateCompleted)
	}
}

func TestAggregateState_AllFailedBecomesFailed(t *testing.T) {
	targets := []JobTarget{{State: TargetStateFailed}, {State: TargetStateFailed}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStateFailed {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateFailed)
	}
}

func TestAggregateState_MixOfCompletedAndFailedBecomesPartial(t *testing.T) {
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateFailed}, {State: TargetStateCompleted}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStatePartial {
		t.Errorf("AggregateState() = %q, want %q", got, JobStatePartial)
	}
}

func TestAggregateState_CancelledJobIsNeverRecomputed(t *testing.T) {
	// A job the operator already cancelled must stay cancelled even if a
	// late-arriving tick sees targets that would otherwise aggregate to
	// something else (e.g. an in-flight target finishing after cancel).
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateCancelled}}
	got := AggregateState(JobStateCancelled, targets)
	if got != JobStateCancelled {
		t.Errorf("AggregateState() = %q, want %q (cancelled is sticky)", got, JobStateCancelled)
	}
}

func TestAggregateState_StillInFlightNotYetTerminal(t *testing.T) {
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateDispatched}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStateRunning {
		t.Errorf("AggregateState() = %q, want %q (one target still dispatched)", got, JobStateRunning)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestAggregateState -v`
Expected: FAIL — package `internal/jobs` doesn't exist yet (build error: no such directory / undefined symbols).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/jobs/types.go
package jobs

import (
	"encoding/json"
	"time"
)

const (
	JobStateRequested = "requested"
	JobStateRunning   = "running"
	JobStateCompleted = "completed" // every target terminal, all succeeded
	JobStatePartial   = "partial"   // every target terminal, some succeeded and some didn't
	JobStateFailed    = "failed"    // every target terminal, none succeeded
	JobStateCancelled = "cancelled"
)

const (
	TargetStatePending    = "pending"
	TargetStateDispatched = "dispatched"
	TargetStateCompleted  = "completed"
	TargetStateFailed     = "failed"
	TargetStateCancelled  = "cancelled"
)

// Job is one logical fleet-wide operation -- e.g. "apply remediation X to
// these N agents". internal/jobs knows nothing about what Type="batch_remediation"
// actually does; that's supplied by internal/api via DispatchFn/StatusFn (dispatch.go).
type Job struct {
	ID          string
	Type        string
	State       string
	Payload     json.RawMessage // type-specific, e.g. {"remediationId":"...","reason":"..."}
	CreatedBy   string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}

// JobTarget is one agent's independently tracked execution within a Job.
type JobTarget struct {
	ID          string
	JobID       string
	AgentID     string
	State       string
	RefID       string // e.g. the remediation_requests.id created for this target, once dispatched
	Error       string
	RetryCount  int // no auto-retry logic built this cycle; column exists for forward-compat
	MaxRetries  int
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}
```

- [ ] **Step 4: Write `state.go`**

```go
// orchestrator/internal/jobs/state.go
package jobs

// AggregateState computes a Job's rolled-up state from its targets'
// current states. A job the operator already cancelled (current ==
// JobStateCancelled) is never recomputed -- that's a sticky, operator-driven
// terminal state, not something a later tick should overwrite even if an
// in-flight target happens to resolve afterward.
func AggregateState(current string, targets []JobTarget) string {
	if current == JobStateCancelled {
		return JobStateCancelled
	}

	var completed, terminal, dispatchedOrTerminal int
	for _, t := range targets {
		switch t.State {
		case TargetStateCompleted:
			completed++
			terminal++
			dispatchedOrTerminal++
		case TargetStateFailed, TargetStateCancelled:
			terminal++
			dispatchedOrTerminal++
		case TargetStateDispatched:
			dispatchedOrTerminal++
		}
	}

	total := len(targets)
	if terminal == total && total > 0 {
		if completed == total {
			return JobStateCompleted
		}
		if completed == 0 {
			return JobStateFailed
		}
		return JobStatePartial
	}
	if dispatchedOrTerminal > 0 {
		return JobStateRunning
	}
	return JobStateRequested
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestAggregateState -v`
Expected: PASS for all 7 tests.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/jobs/types.go orchestrator/internal/jobs/state.go orchestrator/internal/jobs/state_test.go
git commit -m "feat(jobs): add Job/JobTarget types and pure state-aggregation logic"
git push
```

---

### Task 2: `jobs`/`job_targets` schema + `Store` CRUD

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append to the `stmts := []string{...}` slice in `EnsureSchema`, right after `technique_verification_runs`' indexes)
- Create: `orchestrator/internal/jobs/store.go`
- Test: `orchestrator/internal/jobs/store_test.go`

**Interfaces:**
- Consumes: `Job`, `JobTarget`, all `JobState*`/`TargetState*` constants (Task 1).
- Produces: `NewStore(pool *pgxpool.Pool) *Store`; `(s *Store) CreateBatch(ctx, jobType string, payload json.RawMessage, createdBy string, agentIDs []string) (Job, error)`; `(s *Store) Get(ctx, id string) (Job, error)`; `(s *Store) ListTargets(ctx, jobID string) ([]JobTarget, error)`; `(s *Store) ListActiveDispatchedTargets(ctx) ([]JobTarget, error)`; `(s *Store) ListPendingTargetsAcrossActiveJobs(ctx, limit int) ([]JobTarget, error)`; `(s *Store) MarkTargetDispatched(ctx, targetID, refID string) error`; `(s *Store) MarkTargetTerminal(ctx, targetID, state, errText string) error`; `(s *Store) SetJobState(ctx, jobID, state string) error`; `(s *Store) CancelJob(ctx, jobID string) (cancelledCount int, err error)` — Task 3's `Dispatcher` and Tasks 5-7's HTTP handlers consume all of these.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/jobs/store_test.go
package jobs

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestCreateBatch_CreatesJobPlusOneTargetPerAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-a", "agent-b", "agent-c"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if job.ID == "" || job.State != JobStateRequested || job.Type != "batch_remediation" {
			t.Fatalf("job = %+v, want non-empty ID, State=requested, Type=batch_remediation", job)
		}

		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 3 {
			t.Fatalf("ListTargets() = %d rows, want 3", len(targets))
		}
		for _, tg := range targets {
			if tg.State != TargetStatePending {
				t.Errorf("target %s State = %q, want pending", tg.AgentID, tg.State)
			}
		}
	})
}

func TestListPendingTargetsAcrossActiveJobs_RespectsLimitAndOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"a1", "a2", "a3", "a4", "a5"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		got, err := store.ListPendingTargetsAcrossActiveJobs(ctx, 3)
		if err != nil {
			t.Fatalf("ListPendingTargetsAcrossActiveJobs: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("ListPendingTargetsAcrossActiveJobs(limit=3) = %d rows, want 3 (out of 5 pending)", len(got))
		}
		for _, tg := range got {
			if tg.JobID != job.ID {
				t.Errorf("target JobID = %q, want %q", tg.JobID, job.ID)
			}
		}
	})
}

func TestMarkTargetDispatchedThenTerminal_UpdatesState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-x"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		target := targets[0]

		if err := store.MarkTargetDispatched(ctx, target.ID, "ref-123"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}
		dispatched, err := store.ListActiveDispatchedTargets(ctx)
		if err != nil {
			t.Fatalf("ListActiveDispatchedTargets: %v", err)
		}
		found := false
		for _, tg := range dispatched {
			if tg.ID == target.ID && tg.RefID == "ref-123" {
				found = true
			}
		}
		if !found {
			t.Fatalf("ListActiveDispatchedTargets() = %+v, want target %s with RefID=ref-123", dispatched, target.ID)
		}

		if err := store.MarkTargetTerminal(ctx, target.ID, TargetStateFailed, "agent not connected"); err != nil {
			t.Fatalf("MarkTargetTerminal: %v", err)
		}
		final, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if final[0].State != TargetStateFailed || final[0].Error != "agent not connected" || final[0].CompletedAt == nil {
			t.Fatalf("final target = %+v, want State=failed Error='agent not connected' CompletedAt set", final[0])
		}
		stillDispatched, err := store.ListActiveDispatchedTargets(ctx)
		if err != nil {
			t.Fatalf("ListActiveDispatchedTargets: %v", err)
		}
		for _, tg := range stillDispatched {
			if tg.ID == target.ID {
				t.Fatalf("target %s still shows up as dispatched after being marked terminal", target.ID)
			}
		}
	})
}

func TestSetJobState_TerminalStateStampsCompletedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-y"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		if err := store.SetJobState(ctx, job.ID, JobStateRunning); err != nil {
			t.Fatalf("SetJobState(running): %v", err)
		}
		mid, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if mid.State != JobStateRunning || mid.StartedAt == nil || mid.CompletedAt != nil {
			t.Fatalf("mid state = %+v, want State=running StartedAt set CompletedAt nil", mid)
		}

		if err := store.SetJobState(ctx, job.ID, JobStateCompleted); err != nil {
			t.Fatalf("SetJobState(completed): %v", err)
		}
		final, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if final.State != JobStateCompleted || final.CompletedAt == nil {
			t.Fatalf("final state = %+v, want State=completed CompletedAt set", final)
		}
	})
}

func TestCancelJob_CancelsPendingLeavesDispatchedAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-p", "agent-d"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		var dispatchedID string
		for _, tg := range targets {
			if tg.AgentID == "agent-d" {
				dispatchedID = tg.ID
			}
		}
		if err := store.MarkTargetDispatched(ctx, dispatchedID, "ref-d"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}

		cancelled, err := store.CancelJob(ctx, job.ID)
		if err != nil {
			t.Fatalf("CancelJob: %v", err)
		}
		if cancelled != 1 {
			t.Fatalf("CancelJob() cancelled = %d, want 1 (only the still-pending target)", cancelled)
		}

		final, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		for _, tg := range final {
			switch tg.AgentID {
			case "agent-p":
				if tg.State != TargetStateCancelled {
					t.Errorf("agent-p State = %q, want cancelled", tg.State)
				}
			case "agent-d":
				if tg.State != TargetStateDispatched {
					t.Errorf("agent-d State = %q, want dispatched (already in flight, untouched)", tg.State)
				}
			}
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateCancelled {
			t.Errorf("job State = %q, want cancelled", gotJob.State)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: FAIL — `NewStore`/`Store` undefined (compile error); `jobs`/`job_targets` tables don't exist yet.

- [ ] **Step 3: Add the schema**

In `orchestrator/internal/db/postgres.go`, find the `technique_verification_runs` block and its trailing indexes (added in the prior BAS-Verified Remediation sub-project), and append immediately after:

```go
		// jobs / job_targets: generic fleet-job infrastructure. internal/jobs
		// knows nothing about what a given Job.Type actually does -- that's
		// supplied by internal/api at wiring time. See
		// docs/superpowers/specs/2026-08-03-fleet-job-engine-design.md.
		`CREATE TABLE IF NOT EXISTS jobs (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type         text        NOT NULL,
			state        text        NOT NULL,
			payload      jsonb       NOT NULL DEFAULT '{}',
			created_by   text        NOT NULL DEFAULT '',
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			started_at   timestamptz,
			completed_at timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs (state)`,

		`CREATE TABLE IF NOT EXISTS job_targets (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			job_id       text        NOT NULL REFERENCES jobs(id),
			agent_id     text        NOT NULL,
			state        text        NOT NULL,
			ref_id       text        NOT NULL DEFAULT '',
			error        text        NOT NULL DEFAULT '',
			retry_count  int         NOT NULL DEFAULT 0,
			max_retries  int         NOT NULL DEFAULT 0,
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			started_at   timestamptz,
			completed_at timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_job_id ON job_targets (job_id)`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_state ON job_targets (state) WHERE state = 'pending'`,
```

- [ ] **Step 4: Write `store.go`**

```go
// orchestrator/internal/jobs/store.go
package jobs

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// CreateBatch creates a Job plus one JobTarget per agentID, in a single
// transaction so a job never exists with a partial target list.
func (s *Store) CreateBatch(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string) (Job, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback(ctx)

	var jobID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO jobs (type, state, payload, created_by) VALUES ($1,$2,$3,$4) RETURNING id`,
		jobType, JobStateRequested, []byte(payload), createdBy,
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
		`SELECT id, type, state, payload, created_by, created_at, started_at, completed_at FROM jobs WHERE id=$1`, id,
	).Scan(&j.ID, &j.Type, &j.State, &j.Payload, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.CompletedAt)
	return j, err
}

func scanJobTargets(rows pgx.Rows) ([]JobTarget, error) {
	defer rows.Close()
	var out []JobTarget
	for rows.Next() {
		var t JobTarget
		if err := rows.Scan(&t.ID, &t.JobID, &t.AgentID, &t.State, &t.RefID, &t.Error,
			&t.RetryCount, &t.MaxRetries, &t.CreatedAt, &t.StartedAt, &t.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

const jobTargetColumns = `id, job_id, agent_id, state, ref_id, error, retry_count, max_retries, created_at, started_at, completed_at`

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
	return `jt.id, jt.job_id, jt.agent_id, jt.state, jt.ref_id, jt.error, jt.retry_count, jt.max_retries, jt.created_at, jt.started_at, jt.completed_at`
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

// SetJobState persists a Job's aggregate state. StartedAt is stamped the
// first time state moves off "requested" (COALESCE keeps any existing
// value); CompletedAt is stamped whenever state lands in a terminal value.
func (s *Store) SetJobState(ctx context.Context, jobID, state string) error {
	terminal := state == JobStateCompleted || state == JobStatePartial || state == JobStateFailed || state == JobStateCancelled
	if terminal {
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for all tests in the package (7 from Task 1 + 5 new).

- [ ] **Step 6: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/jobs/store.go orchestrator/internal/jobs/store_test.go
git commit -m "feat(jobs): add jobs/job_targets schema and Store CRUD"
git push
```

---

### Task 3: `Dispatcher` + `Tick()`

**Files:**
- Create: `orchestrator/internal/jobs/dispatch.go`
- Test: `orchestrator/internal/jobs/dispatch_test.go`

**Interfaces:**
- Consumes: `Store` and all its methods (Task 2); `Job`, `JobTarget`, state constants (Task 1).
- Produces: `DispatchFn func(ctx context.Context, job Job, target JobTarget) (refID string, err error)`; `StatusFn func(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool)`; `NewDispatcher(store *Store) *Dispatcher`; `(d *Dispatcher) SetDispatch(fn DispatchFn)`; `(d *Dispatcher) SetStatus(fn StatusFn)`; `(d *Dispatcher) Tick(ctx context.Context) error` — Task 4 wires real `DispatchFn`/`StatusFn` implementations in; `main.go` (Task 8) drives `Tick()` from a `PollScheduler`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/jobs/dispatch_test.go
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTick_DispatchesPendingTargetsUpToCap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		agentIDs := make([]string, 0, jobDispatchBatchSize+5)
		for i := 0; i < jobDispatchBatchSize+5; i++ {
			agentIDs = append(agentIDs, "cap-agent-"+string(rune('a'+i)))
		}
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", agentIDs)
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		var dispatchedCount int
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			dispatchedCount++
			return "ref-" + target.AgentID, nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			return TargetStateDispatched, "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if dispatchedCount != jobDispatchBatchSize {
			t.Fatalf("dispatchedCount = %d, want %d (the per-tick cap)", dispatchedCount, jobDispatchBatchSize)
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateRunning {
			t.Errorf("job State = %q, want running (some targets dispatched, some still pending)", gotJob.State)
		}
	})
}

func TestTick_ResolvesTerminalTargetsAndAggregatesJobState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-done"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		if err := store.MarkTargetDispatched(ctx, targets[0].ID, "ref-done"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- the only target is already dispatched")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			if refID == "ref-done" {
				return TargetStateCompleted, "", true
			}
			return TargetStateDispatched, "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateCompleted || gotJob.CompletedAt == nil {
			t.Fatalf("job = %+v, want State=completed CompletedAt set", gotJob)
		}
	})
}

func TestTick_DispatchErrorMarksTargetFailedWithoutAborting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-offline"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			return "", errors.New("agent not connected")
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			t.Fatal("status should not be called -- nothing was dispatched")
			return "", "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick itself should not error (failure is recorded on the target, not returned): %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if targets[0].State != TargetStateFailed || targets[0].Error != "agent not connected" {
			t.Fatalf("target = %+v, want State=failed Error='agent not connected'", targets[0])
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateFailed {
			t.Errorf("job State = %q, want failed (its only target failed)", gotJob.State)
		}
	})
}

func TestTick_CancelledJobIsNeverTouched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-c1", "agent-c2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if _, err := store.CancelJob(ctx, job.ID); err != nil {
			t.Fatalf("CancelJob: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called for a cancelled job")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			t.Fatal("status should not be called for a cancelled job")
			return "", "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestTick -v`
Expected: FAIL — `NewDispatcher`/`Dispatcher` undefined (compile error).

- [ ] **Step 3: Write `dispatch.go`**

```go
// orchestrator/internal/jobs/dispatch.go
package jobs

import "context"

// DispatchFn performs one target's actual execution (e.g. creating a
// remediation_requests row and dispatching it to the agent) and returns a
// RefID to poll for that target's outcome via StatusFn, or an error if
// dispatch itself failed.
type DispatchFn func(ctx context.Context, job Job, target JobTarget) (refID string, err error)

// StatusFn resolves a dispatched target's current state by interpreting
// whatever RefID points at. terminal=false means still in progress -- Tick
// leaves the target alone and checks again next tick.
type StatusFn func(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool)

// jobDispatchBatchSize caps how many pending targets Tick dispatches in a
// single call, mirroring internal/api/revalidation.go's revalidationBatchSize
// reasoning -- a 200-target job shouldn't flood the WS hub and every agent's
// local queue in one pass.
const jobDispatchBatchSize = 20

type Dispatcher struct {
	store    *Store
	dispatch DispatchFn
	status   StatusFn
}

func NewDispatcher(store *Store) *Dispatcher {
	return &Dispatcher{store: store}
}

func (d *Dispatcher) SetDispatch(fn DispatchFn) { d.dispatch = fn }
func (d *Dispatcher) SetStatus(fn StatusFn)     { d.status = fn }

// Tick advances every active job by (1) resolving any in-flight targets
// that have reached a terminal state, (2) dispatching up to
// jobDispatchBatchSize still-pending targets, then (3) recomputing and
// persisting the aggregate state of every job touched in this tick.
func (d *Dispatcher) Tick(ctx context.Context) error {
	jobCache := map[string]Job{}
	jobOf := func(jobID string) (Job, error) {
		if j, ok := jobCache[jobID]; ok {
			return j, nil
		}
		j, err := d.store.Get(ctx, jobID)
		if err == nil {
			jobCache[jobID] = j
		}
		return j, err
	}

	touchedJobs := map[string]bool{}

	inFlight, err := d.store.ListActiveDispatchedTargets(ctx)
	if err != nil {
		return err
	}
	for _, t := range inFlight {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		state, errText, terminal := d.status(ctx, job.Type, t.RefID)
		if !terminal {
			continue
		}
		if err := d.store.MarkTargetTerminal(ctx, t.ID, state, errText); err != nil {
			continue
		}
		touchedJobs[t.JobID] = true
	}

	pending, err := d.store.ListPendingTargetsAcrossActiveJobs(ctx, jobDispatchBatchSize)
	if err != nil {
		return err
	}
	for _, t := range pending {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		refID, dispatchErr := d.dispatch(ctx, job, t)
		if dispatchErr != nil {
			d.store.MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())
		} else {
			d.store.MarkTargetDispatched(ctx, t.ID, refID)
		}
		touchedJobs[t.JobID] = true
	}

	for jobID := range touchedJobs {
		targets, err := d.store.ListTargets(ctx, jobID)
		if err != nil {
			continue
		}
		job, err := jobOf(jobID)
		if err != nil {
			continue
		}
		newState := AggregateState(job.State, targets)
		if newState != job.State {
			if err := d.store.SetJobState(ctx, jobID, newState); err == nil {
				updated := job
				updated.State = newState
				jobCache[jobID] = updated
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for every test in the package.

- [ ] **Step 5: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/jobs/dispatch.go orchestrator/internal/jobs/dispatch_test.go
git commit -m "feat(jobs): add Dispatcher.Tick() -- capped dispatch, terminal resolution, state aggregation"
git push
```

---

### Task 4: Batch-remediation `DispatchFn`/`StatusFn` + `WithJobsDispatcher` wiring

**Files:**
- Create: `orchestrator/internal/api/job_dispatch.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `jobsStore *jobs.Store` field + `WithJobsDispatcher` method, near the existing `vexSweep`/`WithVexSweep` pair)
- Test: `orchestrator/internal/api/job_dispatch_test.go`

**Interfaces:**
- Consumes: `jobs.Job`, `jobs.JobTarget`, `jobs.Store`, `jobs.Dispatcher`, `jobs.TargetState*` (Tasks 1-3); `remediation.CatalogEntry`, `remediation.Status*`, `remediation.OSSupported` (Sub-project 4, already shipped); `h.dispatchRemediationStep`, `h.aggregateAgentResults`, `latestCheckIsPassing`, `newID` (Sub-project 4/existing `internal/api` helpers).
- Produces: `(h *Handler) dispatchBatchRemediationTarget(ctx, job jobs.Job, target jobs.JobTarget) (refID string, err error)` — matches `jobs.DispatchFn`; `(h *Handler) batchRemediationTargetStatus(ctx, jobType, refID string) (state, errText string, terminal bool)` — matches `jobs.StatusFn`; `(h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler`. Tasks 5-7's handlers consume `h.jobsStore`; Task 8's `main.go` wiring consumes `WithJobsDispatcher`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/job_dispatch_test.go
package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestDispatchBatchRemediationTarget_Dispatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-t1', 'JB-T1', 'windows')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "jb-t1")

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, hub, eng, "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job := jobs.Job{ID: "job-1", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-1", JobID: "job-1", AgentID: "jb-t1"}

		refID, err := h.dispatchBatchRemediationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBatchRemediationTarget: %v", err)
		}
		if refID == "" {
			t.Fatal("refID is empty")
		}
		var status, fixRunID string
		if err := pool.QueryRow(context.Background(), `SELECT status, fix_run_id FROM remediation_requests WHERE id=$1`, refID).Scan(&status, &fixRunID); err != nil {
			t.Fatalf("query remediation_requests: %v", err)
		}
		if status != remediation.StatusDispatched || fixRunID == "" {
			t.Errorf("status=%q fixRunID=%q, want status=dispatched and a non-empty fixRunID", status, fixRunID)
		}
	})
}

func TestDispatchBatchRemediationTarget_AlreadyCompliant_MarksCompletedWithoutDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-t2', 'JB-T2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('jb-t2-run', 'windows-security-config', 'Posture Run', 'jb-t2', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-firewall-enabled","result":"pass","executedAt":"2026-08-03T00:00:00Z"}]`)
		eng := scenario.NewEngine(t.TempDir())
		hub := ws.NewHub()

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, hub, eng, "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job := jobs.Job{ID: "job-2", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-2", JobID: "job-2", AgentID: "jb-t2"}

		refID, err := h.dispatchBatchRemediationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBatchRemediationTarget: %v", err)
		}
		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, refID).Scan(&status); err != nil {
			t.Fatalf("query remediation_requests: %v", err)
		}
		if status != remediation.StatusCompleted {
			t.Errorf("status = %q, want completed (already compliant, no dispatch needed)", status)
		}
	})
}

func TestDispatchBatchRemediationTarget_UnknownRemediationID_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-t4', 'JB-T4', 'windows')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(map[string]string{"remediationId": "does_not_exist", "reason": "test"})
		job := jobs.Job{ID: "job-4", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-4", JobID: "job-4", AgentID: "jb-t4"}

		if _, err := h.dispatchBatchRemediationTarget(context.Background(), job, target); err == nil {
			t.Fatal("expected an error for an unknown remediationId")
		}
	})
}

func TestBatchRemediationTargetStatus_MapsRemediationStatusToTargetState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jb-t3', 'JB-T3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-jb-t3', 'enable_windows_firewall', 'jb-t3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		state, errText, terminal := h.batchRemediationTargetStatus(context.Background(), "batch_remediation", "rr-jb-t3")
		if state != jobs.TargetStateCompleted || !terminal || errText != "" {
			t.Errorf("state=%q terminal=%v errText=%q, want completed/true/empty", state, terminal, errText)
		}
	})
}

func TestBatchRemediationTargetStatus_StillRunningIsNotTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jb-t5', 'JB-T5')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-jb-t5', 'enable_windows_firewall', 'jb-t5', 'windows-firewall-enabled', 1, 'verifying', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		state, _, terminal := h.batchRemediationTargetStatus(context.Background(), "batch_remediation", "rr-jb-t5")
		if terminal {
			t.Errorf("terminal = true, want false (status is still 'verifying')")
		}
		if state != jobs.TargetStateDispatched {
			t.Errorf("state = %q, want dispatched (still in progress)", state)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestDispatchBatchRemediationTarget|TestBatchRemediationTargetStatus" -v`
Expected: FAIL — `h.dispatchBatchRemediationTarget`/`h.batchRemediationTargetStatus` undefined (compile error).

- [ ] **Step 3: Write `job_dispatch.go`**

```go
// orchestrator/internal/api/job_dispatch.go
package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
)

// batchRemediationPayload is the Job.Payload shape for Type="batch_remediation".
type batchRemediationPayload struct {
	RemediationID string `json:"remediationId"`
	Reason        string `json:"reason"`
}

// dispatchBatchRemediationTarget is injected into jobs.Dispatcher via
// SetDispatch (see WithJobsDispatcher below). It performs the exact same
// pre-flight + dispatch steps as Sub-project 4's ExecuteRemediation -- the
// permission/Tier-4/catalog-existence checks already happened once, at
// job-creation time (CreateBatchRemediationJob, Task 5), not per-target here.
func (h *Handler) dispatchBatchRemediationTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	var payload batchRemediationPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return "", err
	}
	if h.remediationCatalog == nil {
		return "", errors.New("remediation catalog not loaded")
	}
	entry, ok := h.remediationCatalog.ByID(payload.RemediationID)
	if !ok {
		return "", errors.New("unknown remediationId")
	}

	var agentOS string
	h.db.QueryRow(ctx, `SELECT COALESCE(os_version,'') FROM agents WHERE agent_id=$1`, target.AgentID).Scan(&agentOS)
	if !remediation.OSSupported(agentOS, entry) {
		return "", errors.New("remediation not supported on this endpoint's OS")
	}

	requestID := newID()
	allResults := h.aggregateAgentResults(ctx, target.AgentID)
	if latestCheckIsPassing(allResults, entry.CheckID) {
		if _, err := h.db.Exec(ctx,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, completed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())`,
			requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusCompleted, job.CreatedBy, payload.Reason, entry.SupportsRollback,
		); err != nil {
			return "", err
		}
		return requestID, nil
	}

	if _, err := h.db.Exec(ctx,
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, job.CreatedBy, payload.Reason, entry.SupportsRollback,
	); err != nil {
		return "", err
	}

	timeoutSec := entry.EstimatedTimeSec * 2
	if timeoutSec == 0 {
		timeoutSec = 60
	}
	runID, sent, dispatchErr := h.dispatchRemediationStep(ctx, target.AgentID, "remediation-fix", entry.ID, entry.Command, entry.Executor, timeoutSec)
	if dispatchErr != nil {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error=$2 WHERE id=$3`, remediation.StatusFailed, dispatchErr.Error(), requestID)
		return "", dispatchErr
	}
	if !sent {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='agent not connected' WHERE id=$2`, remediation.StatusFailed, requestID)
		return "", errors.New("agent not connected")
	}
	h.db.Exec(ctx,
		`UPDATE remediation_requests SET status=$1, fix_run_id=$2, dispatched_at=NOW() WHERE id=$3`,
		remediation.StatusDispatched, runID, requestID)
	return requestID, nil
}

// batchRemediationTargetStatus is injected into jobs.Dispatcher via
// SetStatus. It polls the remediation_requests row created for this target
// (refID) and reports whether that row has reached a terminal state.
func (h *Handler) batchRemediationTargetStatus(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	var status, errCol string
	if err := h.db.QueryRow(ctx, `SELECT status, error FROM remediation_requests WHERE id=$1`, refID).Scan(&status, &errCol); err != nil {
		return jobs.TargetStateFailed, "remediation request not found: " + err.Error(), true
	}
	switch status {
	case remediation.StatusCompleted:
		return jobs.TargetStateCompleted, "", true
	case remediation.StatusFailed, remediation.StatusVerificationFailed, remediation.StatusTimedOut, remediation.StatusCancelled:
		return jobs.TargetStateFailed, errCol, true
	default: // requested, dispatched, running, verifying
		return jobs.TargetStateDispatched, "", false
	}
}

// WithJobsDispatcher wires the Fleet Job Engine's one V1 consumer (batch
// remediation) into dispatcher, and stores store for Tasks 5-7's HTTP
// handlers. Mirrors WithVexSweep's exact shape.
func (h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler {
	h.jobsStore = store
	dispatcher.SetDispatch(h.dispatchBatchRemediationTarget)
	dispatcher.SetStatus(h.batchRemediationTargetStatus)
	return h
}
```

- [ ] **Step 4: Add the `jobsStore` field to `Handler`**

In `orchestrator/internal/api/handlers.go`, find the `vexSweep *vexsweep.Store` field declaration inside the `Handler` struct and add immediately after it:

```go
	jobsStore             *jobs.Store          // nil when not loaded -- Fleet Job Engine (batch remediation)
```

Add `"github.com/audspect/bas/internal/jobs"` to `handlers.go`'s import block (alongside the existing `"github.com/audspect/bas/internal/vexsweep"` import).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestDispatchBatchRemediationTarget|TestBatchRemediationTargetStatus" -v`
Expected: PASS for all 5 tests.

- [ ] **Step 6: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/job_dispatch.go orchestrator/internal/api/job_dispatch_test.go orchestrator/internal/api/handlers.go
git commit -m "feat(api): add batch-remediation DispatchFn/StatusFn and WithJobsDispatcher wiring"
git push
```

---

### Task 5: `POST /api/jobs/batch-remediation`

**Files:**
- Create: `orchestrator/internal/api/job_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/job_handlers_test.go`

**Interfaces:**
- Consumes: `h.jobsStore` (Task 4); `h.remediationCatalog`, `remediation.CatalogEntry`, `remediation.TierManualGuidance`, `remediation.TierConfirmRequired`, `auth.ClaimsFrom`, `auth.HasPermission`, `auth.CanApproveRemediation`, `auth.CanExecuteRemediation` (all pre-existing, Sub-project 4).
- Produces: `(h *Handler) CreateBatchRemediationJob(w http.ResponseWriter, r *http.Request)` — `POST /api/jobs/batch-remediation`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/job_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateBatchRemediationJob_CreatesJobWithOneTargetPerAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbh-a1', 'JBH-A1')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbh-a2', 'JBH-A2')`)

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test batch",
			"agentIds":      []string{"jbh-a1", "jbh-a2"},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			JobID       string `json:"jobId"`
			TargetCount int    `json:"targetCount"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.TargetCount != 2 {
			t.Errorf("targetCount = %d, want 2", resp.TargetCount)
		}
		targets, err := jobsStore.ListTargets(req.Context(), resp.JobID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 2 {
			t.Fatalf("ListTargets() = %d rows, want 2", len(targets))
		}
	})
}

func TestCreateBatchRemediationJob_Tier2WithoutApprovePermission_Forbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbh-a3', 'JBH-A3')`)

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "disable_windows_smbv1", // Tier 2
			"reason":        "test batch",
			"agentIds":      []string{"jbh-a3"},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (Tier 2 requires an Administrator)", w.Code)
		}
	})
}

func TestCreateBatchRemediationJob_TierManualGuidance_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_bitlocker", // Tier 4, manual guidance only
			"reason":        "test batch",
			"agentIds":      []string{"jbh-a4"},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (Tier 4 is manual guidance only)", w.Code)
		}
	})
}

func TestCreateBatchRemediationJob_EmptyAgentIds_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test batch",
			"agentIds":      []string{},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (empty agentIds)", w.Code)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateBatchRemediationJob -v`
Expected: FAIL — `h.CreateBatchRemediationJob` undefined (compile error).

- [ ] **Step 3: Write `job_handlers.go`**

```go
// orchestrator/internal/api/job_handlers.go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/jobs/batch-remediation
// Same tier-gated permission logic as Sub-project 4's ExecuteRemediation --
// batch dispatch of a Tier 2 remediation to 50 machines is not a lesser
// action than dispatching it to one, so it gets no separate, weaker policy.
func (h *Handler) CreateBatchRemediationJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemediationID string   `json:"remediationId"`
		Reason        string   `json:"reason"`
		AgentIDs      []string `json:"agentIds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.RemediationID == "" {
		jsonError(w, "remediationId is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 {
		jsonError(w, "agentIds must contain at least one agent", http.StatusBadRequest)
		return
	}
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok {
		jsonError(w, "unknown remediationId", http.StatusNotFound)
		return
	}
	if entry.Tier == remediation.TierManualGuidance {
		jsonError(w, "this remediation is manual guidance only -- no automatic execution", http.StatusUnprocessableEntity)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	if entry.Tier == remediation.TierConfirmRequired && (claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation)) {
		jsonError(w, "this remediation requires an Administrator", http.StatusForbidden)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	payload, err := json.Marshal(map[string]string{"remediationId": entry.ID, "reason": req.Reason})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	job, err := h.jobsStore.CreateBatch(r.Context(), "batch_remediation", payload, actorID, req.AgentIDs)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.batch_remediation.create", job.ID,
		map[string]any{"remediationId": entry.ID, "agentCount": len(req.AgentIDs)}, "created")
	respond(w, map[string]any{"jobId": job.ID, "state": job.State, "targetCount": len(req.AgentIDs)})
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, right after the `remediation-reports/summary` route:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/jobs/batch-remediation", h.CreateBatchRemediationJob)
```

- [ ] **Step 5: Add the row to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the `remediation-reports/summary` row:

```go
	{http.MethodPost, "/api/jobs/batch-remediation", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateBatchRemediationJob|TestRBACMatrix" -v`
Expected: PASS for all 4 new tests plus `TestRBACMatrix_NoDrift`/`TestRBACMatrix_MethodConfusion`.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/job_handlers.go orchestrator/internal/api/job_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add POST /api/jobs/batch-remediation"
git push
```

---

### Task 6: `GET /api/jobs/{jobId}`

**Files:**
- Modify: `orchestrator/internal/api/job_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Modify: `orchestrator/internal/api/job_handlers_test.go`

**Interfaces:**
- Consumes: `h.jobsStore.Get`/`.ListTargets` (Task 2); `withURLParam` test helper (pre-existing).
- Produces: `(h *Handler) GetJob(w http.ResponseWriter, r *http.Request)` — `GET /api/jobs/{jobId}`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/job_handlers_test.go` (add `"github.com/go-chi/chi/v5"` is NOT needed here -- `withURLParam` already wraps `chi.URLParam` internally, matching every other handler test in this file):

```go
func TestGetJob_ReturnsJobAndTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbg-a1', 'JBG-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"jbg-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "jobId", created.ID)
		w := httptest.NewRecorder()
		h.GetJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Job     jobs.Job          `json:"job"`
			Targets []jobs.JobTarget  `json:"targets"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Job.ID != created.ID || len(resp.Targets) != 1 {
			t.Errorf("resp = %+v, want Job.ID=%s and 1 target", resp, created.ID)
		}
	})
}

func TestGetJob_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "jobId", "no-such-job")
		w := httptest.NewRecorder()
		h.GetJob(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}
```

Add `"context"` and `"github.com/audspect/bas/internal/jobs"` to `job_handlers_test.go`'s import block if not already present from Task 5.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetJob -v`
Expected: FAIL — `h.GetJob` undefined (compile error).

- [ ] **Step 3: Add `GetJob` to `job_handlers.go`**

Append to `orchestrator/internal/api/job_handlers.go`:

```go
// GET /api/jobs/{jobId}
func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	job, err := h.jobsStore.Get(r.Context(), jobID)
	if err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	targets, err := h.jobsStore.ListTargets(r.Context(), jobID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"job": job, "targets": targets})
}
```

Add `"github.com/go-chi/chi/v5"` to `job_handlers.go`'s import block.

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, right after the `POST /api/jobs/batch-remediation` route (matches Sub-project 4's `GetRemediation`/`ListAgentRemediations` precedent -- read-only job status is gated behind the same `CanExecuteRemediation` permission as the write path, not opened to Viewer):

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/jobs/{jobId}", h.GetJob)
```

- [ ] **Step 5: Add the row to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the `POST /api/jobs/batch-remediation` row:

```go
	{http.MethodGet, "/api/jobs/{jobId}", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetJob|TestRBACMatrix" -v`
Expected: PASS for both new tests plus `TestRBACMatrix_NoDrift`/`TestRBACMatrix_MethodConfusion`.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/job_handlers.go orchestrator/internal/api/job_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add GET /api/jobs/{jobId}"
git push
```

---

### Task 7: `POST /api/jobs/{jobId}/cancel`

**Files:**
- Modify: `orchestrator/internal/api/job_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Modify: `orchestrator/internal/api/job_handlers_test.go`

**Interfaces:**
- Consumes: `h.jobsStore.Get`/`.CancelJob` (Task 2).
- Produces: `(h *Handler) CancelJob(w http.ResponseWriter, r *http.Request)` — `POST /api/jobs/{jobId}/cancel`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/job_handlers_test.go`:

```go
func TestCancelJob_CancelsPendingTargetsAndJob(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbc-a1', 'JBC-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"jbc-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "jobId", created.ID)
		w := httptest.NewRecorder()
		h.CancelJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		got, err := jobsStore.Get(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.State != jobs.JobStateCancelled {
			t.Errorf("job State = %q, want cancelled", got.State)
		}
	})
}

func TestCancelJob_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "jobId", "no-such-job")
		w := httptest.NewRecorder()
		h.CancelJob(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestCancelJob -v`
Expected: FAIL — `h.CancelJob` undefined (compile error).

- [ ] **Step 3: Add `CancelJob` to `job_handlers.go`**

Append to `orchestrator/internal/api/job_handlers.go`:

```go
// POST /api/jobs/{jobId}/cancel
// Cancels every still-pending target and the job itself. Targets already
// dispatched are untouched -- that WS message already went out; an
// operator cancels an in-flight target individually via Sub-project 4's
// existing POST /api/remediation-requests/{requestId}/cancel using the
// target's RefID.
func (h *Handler) CancelJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.jobsStore.Get(r.Context(), jobID); err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	cancelledCount, err := h.jobsStore.CancelJob(r.Context(), jobID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.cancel", jobID, map[string]any{"cancelledTargets": cancelledCount}, "cancelled")
	respond(w, map[string]any{"jobId": jobID, "state": jobs.JobStateCancelled, "cancelledTargets": cancelledCount})
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, right after the `GET /api/jobs/{jobId}` route (matches Sub-project 4's `CancelRemediation` precedent -- gated at the same `CanExecuteRemediation` level, not the stronger `CanApproveRemediation`):

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/jobs/{jobId}/cancel", h.CancelJob)
```

- [ ] **Step 5: Add the row to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the `GET /api/jobs/{jobId}` row:

```go
	{http.MethodPost, "/api/jobs/{jobId}/cancel", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCancelJob|TestRBACMatrix" -v`
Expected: PASS for both new tests plus `TestRBACMatrix_NoDrift`/`TestRBACMatrix_MethodConfusion`.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/job_handlers.go orchestrator/internal/api/job_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add POST /api/jobs/{jobId}/cancel"
git push
```

---

### Task 8: Wire into `main.go` + full verification pass

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `jobs.NewStore`, `jobs.NewDispatcher`, `(h *Handler) WithJobsDispatcher` (Tasks 2-4); `exercise.NewPollScheduler` (pre-existing).

- [ ] **Step 1: Wire the Job Engine into `main.go`**

In `orchestrator/cmd/server/main.go`, find the "Full Variant Sweep" block (`vexSweepStore := vexsweep.NewStore(pool)` through `vexSweepDispatcher := vexsweep.NewDispatcher(...)`) and add immediately after it:

```go
	// Fleet Job Engine -- generic Job/JobTarget infrastructure. Ticks every
	// 5s, same cadence as vexSweepScheduler. internal/jobs knows nothing
	// about remediation; WithJobsDispatcher (below) wires in the one V1
	// consumer, batch remediation.
	jobsStore := jobs.NewStore(pool)
	jobsDispatcher := jobs.NewDispatcher(jobsStore)
	jobsScheduler := exercise.NewPollScheduler(5 * time.Second)
```

Add `"github.com/audspect/bas/internal/jobs"` to `main.go`'s import block.

- [ ] **Step 2: Add `.WithJobsDispatcher(...)` to the handler chain**

In the `handler := api.New(pool, hub, engine, cfg.JWTSecret).` builder chain, add a new line right after `.WithRemediationCatalog(remediationCatalog).`:

```go
		WithJobsDispatcher(jobsStore, jobsDispatcher).
```

- [ ] **Step 3: Start the scheduler**

Right after the existing `vexSweepScheduler.Start(...)` / `defer vexSweepScheduler.Stop()` block, add:

```go
	jobsScheduler.Start(func(ctx context.Context) {
		if err := jobsDispatcher.Tick(ctx); err != nil {
			log.Printf("[jobs] tick: %v", err)
		}
	})
	defer jobsScheduler.Stop()
```

- [ ] **Step 4: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 5: Full test suite for every touched package**

Run: `cd orchestrator && go test ./internal/jobs/... ./internal/api/... ./internal/remediation/... ./internal/auth/... -v 2>&1 | tail -150`
Expected: PASS, zero failures. (`internal/remediation`/`internal/auth` are included as a regression check -- this plan never modifies either package, so their existing suites should be unaffected.)

- [ ] **Step 6: Confirm the RBAC route matrix has zero drift against the live router**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS.

- [ ] **Step 7: No commit needed for verification alone -- commit only the `main.go` wiring**

```bash
git add orchestrator/cmd/server/main.go
git commit -m "feat(main): wire Fleet Job Engine into server startup"
git push
```

---

## Self-Review Notes

- **Spec coverage**: §3 (architecture, sibling package, no import cycle) → Tasks 1-4. §4 (data model, `Job`/`JobTarget`, `jobs`/`job_targets` schema, `CreatedAt` fix) → Tasks 1-2. §5 (dispatch loop, `DispatchFn`/`StatusFn`, `jobDispatchBatchSize`, three-step `Tick()`) → Task 3. §6 (API surface, all 3 routes, tier-gated permission reuse, cancel semantics) → Tasks 5-7. §7 (error handling -- dispatch failure marks target failed without aborting the batch; zero-completed job is `failed` not `completed`) → Task 3's `TestTick_DispatchErrorMarksTargetFailedWithoutAborting` and Task 1's `AggregateState` tests. §8 (testing) → every task's own tests plus Task 8's full-suite run. §9 (explicitly deferred) → no task builds any of that scope, correctly.
- **Placeholder scan**: none found -- every step has complete, real code; no TBD/TODO.
- **Type consistency checked**: `Job`/`JobTarget` field names, `AggregateState`, `DispatchFn`/`StatusFn` signatures, `Store` method names (`CreateBatch`, `Get`, `ListTargets`, `ListActiveDispatchedTargets`, `ListPendingTargetsAcrossActiveJobs`, `MarkTargetDispatched`, `MarkTargetTerminal`, `SetJobState`, `CancelJob`), `Dispatcher.Tick`, `dispatchBatchRemediationTarget`, `batchRemediationTargetStatus`, and `WithJobsDispatcher` all match verbatim between their defining task and every consuming task.
- **No temporary build breaks**: task order is types/pure-logic → schema/store → dispatcher → batch-remediation consumer functions → 3 HTTP handlers (in dependency order: create, then read, then cancel) → main.go wiring, so every dependency exists before its first consumer; `go build ./...` stays green after every task.
