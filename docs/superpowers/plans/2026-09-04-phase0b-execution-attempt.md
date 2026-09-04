# Phase 0B: Unified ExecutionAttempt Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the `execution_attempts` table and wire both execution engines (ART/Caldera `scenario_runs` and `internal/exercise` `StepExecution`) to write to it, giving Phase 0C a single queryable record of "did an executable unit run, and what happened."

**Architecture:** One new table, populated by two write-side integrations at existing call sites (no new dispatch/scoring logic). ART/Caldera writes at run granularity via direct `h.db.Exec` calls (matching handlers.go's existing pattern); exercise writes at step granularity via a new `exercise.Store` method (matching that package's existing `UpsertStepExecution` pattern).

**Tech Stack:** Go, pgx/v5, Postgres (schema via `internal/db/postgres.go`'s `EnsureSchema` statement list — this codebase has no separate migration files)

**Spec:** [docs/superpowers/specs/2026-09-04-phase0b-execution-attempt-design.md](../specs/2026-09-04-phase0b-execution-attempt-design.md)

## Global Constraints

- No changes to `scenario_runs`, `exercise_step_executions`, scoring, or dispatch logic — purely additive
- `id` columns in this codebase use `text PRIMARY KEY DEFAULT gen_random_uuid()::text`, not native `UUID` type (see `scenario_runs`, `agents` tables) — schema must match this convention
- Schema changes go into `internal/db/postgres.go`'s `stmts` slice inside `EnsureSchema`, appended before the closing `}` at line 1722 — no separate `.sql` files exist in this codebase
- `internal/exercise`'s `StepExecution.Attempt` field retry-tracking gap (confirmed dead, never incremented) is accepted as-is per the spec — do not attempt to fix it in this plan

---

## File Structure

**Files to modify:**
- `orchestrator/internal/db/postgres.go` — add `execution_attempts` table to `EnsureSchema`'s `stmts` slice
- `orchestrator/internal/models/schema.go` — add `ExecutionAttempt` Go struct
- `orchestrator/internal/api/handlers.go` — write-side integration for ART/Caldera (5 call sites: `dispatchRun`'s two dispatch branches, `SubmitScenarioResult`, plus `liveness.go`'s `ReapStaleRuns`/`ReapAbandonedRuns`, plus `cancelScenarioRun`)
- `orchestrator/internal/exercise/store.go` — new `UpsertExecutionAttempt` method, mirrors `UpsertStepExecution`'s existing shape
- `orchestrator/internal/exercise/executor.go` — write-side integration alongside existing `UpsertStepExecution` calls

**Files to create:**
- `orchestrator/internal/models/execution_attempt_test.go` — struct/constant tests
- `orchestrator/internal/api/execution_attempt_handlers_test.go` — ART/Caldera write-side integration tests
- `orchestrator/internal/exercise/execution_attempt_test.go` — exercise write-side integration tests

---

## Task 1: Schema — `execution_attempts` table

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:1721-1722` (insert before the closing `}` of the `stmts` slice, after the last existing statement)

**Interfaces:**
- Produces: `execution_attempts` table, columns exactly as specified below, consumed by all later tasks

- [ ] **Step 1: Read the exact insertion point**

```bash
sed -n '1715,1725p' orchestrator/internal/db/postgres.go
```

Confirm line 1721 is the last statement (`INSERT INTO finding_slas ...`) and line 1722 is the closing `}` of the `stmts` slice.

- [ ] **Step 2: Insert the new table statement**

Add this as a new element in the `stmts` slice, right before the closing `}`:

```go
		`CREATE TABLE IF NOT EXISTS execution_attempts (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source              text        NOT NULL CHECK (source IN ('art', 'caldera', 'exercise')),
			granularity         text        NOT NULL CHECK (granularity IN ('run', 'step')),
			source_execution_id text        NOT NULL,
			source_attempt_id   text        NOT NULL,
			technique_id        text,

			status              text        NOT NULL CHECK (status IN (
				'pending','dispatched','running','completed','timed_out',
				'cancelled','abandoned','failed_to_dispatch','skipped'
			)),
			skip_reason         text,

			created_at          timestamptz NOT NULL DEFAULT NOW(),
			dispatch_queued_at  timestamptz,
			dispatch_sent_at    timestamptz,
			started_at          timestamptz,
			completed_at        timestamptz,
			decision_at         timestamptz,

			result              jsonb,

			CONSTRAINT execution_attempts_skip_reason_ck CHECK (
				(status = 'skipped' AND skip_reason IS NOT NULL) OR
				(status <> 'skipped' AND skip_reason IS NULL)
			),
			CONSTRAINT execution_attempts_decision_at_ck CHECK (
				(status = 'skipped' AND decision_at IS NOT NULL) OR
				(status <> 'skipped' AND decision_at IS NULL)
			),
			UNIQUE (source, source_attempt_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_execution_attempts_execution ON execution_attempts(source_execution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_execution_attempts_technique ON execution_attempts(technique_id) WHERE technique_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_execution_attempts_status ON execution_attempts(status)`,
```

- [ ] **Step 3: Verify it compiles**

```bash
cd orchestrator && go build ./...
```

Expected: no errors (this is a string literal change, should always compile — this step catches a stray syntax typo in the Go slice literal itself).

- [ ] **Step 4: Commit**

```bash
git add internal/db/postgres.go
git commit -m "feat(phase0b): add execution_attempts table schema"
```

---

## Task 2: Go model — `ExecutionAttempt` struct + status constants

**Files:**
- Modify: `orchestrator/internal/models/schema.go` (append after the existing `StepTermination` struct, which ends around line 136 per earlier session investigation — confirm exact line with grep before editing)
- Create: `orchestrator/internal/models/execution_attempt_test.go`

**Interfaces:**
- Produces: `models.ExecutionAttempt` struct, `models.ExecutionAttemptStatus` type + 9 constants, `models.SkipReason` type + 4 constants — consumed by Tasks 3 and 4

- [ ] **Step 1: Find the exact insertion point**

```bash
grep -n "^type StepTermination struct" -A 10 orchestrator/internal/models/schema.go
```

Confirm the struct's closing `}` line number.

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/models/execution_attempt_test.go
package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExecutionAttemptJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	ea := ExecutionAttempt{
		ID:                 "attempt-1",
		Source:              ExecutionSourceART,
		Granularity:         GranularityRun,
		SourceExecutionID:   "run-1",
		SourceAttemptID:     "run-1",
		Status:              ExecutionAttemptCompleted,
		CreatedAt:           now,
		DispatchQueuedAt:    &now,
		DispatchSentAt:      &now,
		CompletedAt:         &now,
	}
	data, err := json.Marshal(ea)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ExecutionAttempt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != ea.ID || got.Status != ea.Status {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, ea)
	}
}

func TestSkipReasonConstants(t *testing.T) {
	reasons := []SkipReason{
		SkipReasonConditionFalse,
		SkipReasonPrerequisiteUnsatisfied,
		SkipReasonCancelledBeforeDispatch,
		SkipReasonDependencyFailed,
	}
	for _, r := range reasons {
		if r == "" {
			t.Fatal("skip reason constant must not be empty string")
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/models/... -run "TestExecutionAttemptJSONRoundTrip|TestSkipReasonConstants" -v
```

Expected: FAIL with "undefined: ExecutionAttempt" (or similar — the type doesn't exist yet)

- [ ] **Step 4: Write the struct and constants**

Append to `orchestrator/internal/models/schema.go`, after `StepTermination`'s closing `}`:

```go
// ExecutionSource identifies which framework produced an ExecutionAttempt.
type ExecutionSource string

const (
	ExecutionSourceART      ExecutionSource = "art"
	ExecutionSourceCaldera  ExecutionSource = "caldera"
	ExecutionSourceExercise ExecutionSource = "exercise"
)

// ExecutionGranularity distinguishes a run-level attempt (ART/Caldera today
// -- the agent executes a whole scenario in one round trip and reports back
// once) from a step-level attempt (internal/exercise, which already tracks
// per-step state via StepExecution).
type ExecutionGranularity string

const (
	GranularityRun  ExecutionGranularity = "run"
	GranularityStep ExecutionGranularity = "step"
)

// ExecutionAttemptStatus answers "did execution happen?" -- deliberately
// separate from scoring verdict (PASS/FAIL/ERROR/SKIPPED), which answers
// "what did the execution mean?". A completed attempt can score FAIL; that
// is not a contradiction.
type ExecutionAttemptStatus string

const (
	ExecutionAttemptPending           ExecutionAttemptStatus = "pending"
	ExecutionAttemptDispatched        ExecutionAttemptStatus = "dispatched"
	ExecutionAttemptRunning           ExecutionAttemptStatus = "running"
	ExecutionAttemptCompleted         ExecutionAttemptStatus = "completed"
	ExecutionAttemptTimedOut          ExecutionAttemptStatus = "timed_out"
	ExecutionAttemptCancelled         ExecutionAttemptStatus = "cancelled"
	ExecutionAttemptAbandoned         ExecutionAttemptStatus = "abandoned"
	ExecutionAttemptFailedToDispatch  ExecutionAttemptStatus = "failed_to_dispatch"
	ExecutionAttemptSkipped           ExecutionAttemptStatus = "skipped"
)

// SkipReason explains WHY an ExecutionAttempt has status=skipped. Extensible
// application-level vocabulary, not a DB enum -- new values can be added
// without a migration.
type SkipReason string

const (
	SkipReasonConditionFalse          SkipReason = "condition_false"
	SkipReasonPrerequisiteUnsatisfied SkipReason = "prerequisite_unsatisfied"
	SkipReasonCancelledBeforeDispatch SkipReason = "scenario_cancelled_before_dispatch"
	SkipReasonDependencyFailed        SkipReason = "dependency_failed"
)

// ExecutionAttempt is the unified execution-lifecycle record spanning both
// execution engines (ART/Caldera scenario_runs and internal/exercise). See
// docs/superpowers/specs/2026-09-04-phase0b-execution-attempt-design.md.
//
// SourceExecutionID and SourceAttemptID are deliberately loose text fields,
// not real foreign keys -- SourceExecutionID points into either
// scenario_runs.id or exercise Execution.ID depending on Source, and a real
// FK would force picking one, breaking the unification.
type ExecutionAttempt struct {
	ID                  string                  `json:"id,omitempty"`
	Source              ExecutionSource         `json:"source"`
	Granularity         ExecutionGranularity    `json:"granularity"`
	SourceExecutionID   string                  `json:"sourceExecutionId"`
	SourceAttemptID     string                  `json:"sourceAttemptId"`
	TechniqueID         string                  `json:"techniqueId,omitempty"`

	Status              ExecutionAttemptStatus  `json:"status"`
	SkipReason          SkipReason              `json:"skipReason,omitempty"`

	CreatedAt           time.Time               `json:"createdAt"`
	DispatchQueuedAt    *time.Time              `json:"dispatchQueuedAt,omitempty"`
	DispatchSentAt      *time.Time              `json:"dispatchSentAt,omitempty"`
	StartedAt           *time.Time              `json:"startedAt,omitempty"`
	CompletedAt         *time.Time              `json:"completedAt,omitempty"`
	DecisionAt          *time.Time              `json:"decisionAt,omitempty"`

	Result              map[string]interface{}  `json:"result,omitempty"`
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/models/... -run "TestExecutionAttemptJSONRoundTrip|TestSkipReasonConstants" -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/models/schema.go internal/models/execution_attempt_test.go
git commit -m "feat(phase0b): add ExecutionAttempt Go model + status/skip-reason constants"
```

---

## Task 3: ART/Caldera write-side integration

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` — 5 call sites (see steps below)
- Modify: `orchestrator/internal/api/liveness.go` — `ReapStaleRuns` and `ReapAbandonedRuns`
- Create: `orchestrator/internal/api/execution_attempt_handlers_test.go`

**Interfaces:**
- Consumes: `models.ExecutionAttempt`, `models.ExecutionSource{ART,Caldera}`, `models.GranularityRun`, `models.ExecutionAttempt{Pending,Dispatched,Completed,TimedOut,Cancelled,Abandoned,FailedToDispatch}` (Task 2)
- Produces: `insertExecutionAttempt`, `updateExecutionAttemptStatus` helper functions on `*Handler`, used by Task 4's tests as a pattern reference

- [ ] **Step 1: Write the failing test — pending row created on dispatch**

```go
// orchestrator/internal/api/execution_attempt_handlers_test.go
package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDispatchRun_CreatesExecutionAttemptRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		agentID := "agent-ea-dispatch"
		seedActiveAgent(t, pool, agentID, "Linux")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		sc, _ := minimalLiveScenario(t, "int-ea-dispatch")
		ctx := context.Background()
		runID, skipReason, err := h.dispatchRun(ctx, sc, agentID, dispatchOpts{Mode: "telemetry", ConfirmLive: true})
		if err != nil || skipReason != "" {
			t.Fatalf("dispatchRun failed: runID=%s skipReason=%s err=%v", runID, skipReason, err)
		}

		var source, granularity, status, sourceAttemptID string
		if err := pool.QueryRow(ctx,
			`SELECT source, granularity, status, source_attempt_id FROM execution_attempts WHERE source_execution_id = $1`,
			runID,
		).Scan(&source, &granularity, &status, &sourceAttemptID); err != nil {
			t.Fatalf("query execution_attempts: %v", err)
		}
		if granularity != "run" {
			t.Errorf("granularity = %q, want run", granularity)
		}
		if status != "dispatched" {
			t.Errorf("status = %q, want dispatched (dispatch succeeded)", status)
		}
		if sourceAttemptID != runID {
			t.Errorf("source_attempt_id = %q, want %q (same as run ID)", sourceAttemptID, runID)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/api/... -run TestDispatchRun_CreatesExecutionAttemptRow -v -short=false
```

Expected: FAIL — `execution_attempts` row not found (no write-side code exists yet). Requires `TEST_DATABASE_URL` set; if not set locally, this step is verified on the next CI/staging run instead — proceed to implementation regardless, per the plan's TDD structure.

- [ ] **Step 3: Add insert/update helper functions**

Add near the top of `handlers.go`, after the existing `errRunNotFound`/`errRunNotRunning`/`errAgentOffline` sentinel error declarations (search for those to find the right area):

```go
// insertExecutionAttempt creates a 'pending' ExecutionAttempt row for a new
// ART/Caldera scenario_runs dispatch. See
// docs/superpowers/specs/2026-09-04-phase0b-execution-attempt-design.md.
func (h *Handler) insertExecutionAttempt(ctx context.Context, source models.ExecutionSource, runID string) error {
	_, err := h.db.Exec(ctx,
		`INSERT INTO execution_attempts
			(source, granularity, source_execution_id, source_attempt_id, status, created_at)
		 VALUES ($1, 'run', $2, $2, 'pending', NOW())
		 ON CONFLICT (source, source_attempt_id) DO NOTHING`,
		string(source), runID,
	)
	return err
}

// updateExecutionAttemptStatus transitions an existing ExecutionAttempt row.
// timestampCol must be one of the known timestamp column names -- callers
// pass a fixed string literal, never user input, so this is not a SQL
// injection risk despite the string concatenation.
func (h *Handler) updateExecutionAttemptStatus(ctx context.Context, runID, status, timestampCol string) error {
	q := fmt.Sprintf(
		`UPDATE execution_attempts SET status = $1, %s = NOW() WHERE source_attempt_id = $2`,
		timestampCol,
	)
	_, err := h.db.Exec(ctx, q, status, runID)
	return err
}

// markExecutionAttemptSkipped transitions an ExecutionAttempt to skipped,
// satisfying the schema's skip_reason/decision_at CHECK constraints.
func (h *Handler) markExecutionAttemptSkipped(ctx context.Context, runID string, reason models.SkipReason) error {
	_, err := h.db.Exec(ctx,
		`UPDATE execution_attempts SET status = 'skipped', skip_reason = $1, decision_at = NOW() WHERE source_attempt_id = $2`,
		string(reason), runID,
	)
	return err
}
```

- [ ] **Step 4: Wire into dispatchRun's INSERT point**

In `dispatchRun` (handlers.go, around line 1748-1769 per earlier session investigation), right after the `scenario_runs` INSERT succeeds:

```go
	if err != nil {
		if isUniqueViolation(err) {
			return "", "agent busy", nil
		}
		return "", "", err
	}
	// Phase 0B: create the ExecutionAttempt row for this run.
	source := models.ExecutionSourceART
	if strings.Contains(strings.ToLower(sc.ID), "caldera") || len(o.Abilities) > 0 {
		source = models.ExecutionSourceCaldera
	}
	if err := h.insertExecutionAttempt(ctx, source, runID); err != nil {
		log.Printf("[phase0b] insert execution_attempt for run %s: %v", runID, err)
	}
```

- [ ] **Step 5: Wire into the posture/local_check dispatch branch**

In the same function, the `if !live && sc.LocalCheck` block (around line 1781-1797):

```go
		sent := h.hub.SendToAgent(agentID, models.WSMessage{...})
		if !sent {
			h.markRunFailed(context.Background(), runID, "Agent is offline — could not deliver the run")
			_ = h.updateExecutionAttemptStatus(context.Background(), runID, "failed_to_dispatch", "dispatch_sent_at")
			return "", "offline", nil
		}
		if err := h.updateExecutionAttemptStatus(ctx, runID, "dispatched", "dispatch_sent_at"); err != nil {
			log.Printf("[phase0b] update execution_attempt dispatched for run %s: %v", runID, err)
		}
		log.Printf("[perf] execution_id=%s dispatch_sent_at=%s", runID, time.Now().UTC().Format(time.RFC3339Nano))
		log.Printf("[scenario] dispatched posture-check %s → agent %s (run %s)", sc.ID, agentID, runID)
		return runID, "", nil
```

- [ ] **Step 6: Wire into the live ART/Caldera dispatch branch**

At the live-mode `SendToAgent` call (around line 2013-2024):

```go
	sent := h.hub.SendToAgent(agentID, models.WSMessage{...})
	if !sent {
		h.markRunFailed(context.Background(), runID, "Agent is offline — could not deliver the run")
		_ = h.updateExecutionAttemptStatus(context.Background(), runID, "failed_to_dispatch", "dispatch_sent_at")
		return "", "offline", nil
	}
	if err := h.updateExecutionAttemptStatus(ctx, runID, "dispatched", "dispatch_sent_at"); err != nil {
		log.Printf("[phase0b] update execution_attempt dispatched for run %s: %v", runID, err)
	}
	log.Printf("[perf] execution_id=%s dispatch_sent_at=%s", runID, time.Now().UTC().Format(time.RFC3339Nano))
	log.Printf("[scenario] dispatched %s → agent %s (run %s)", sc.ID, agentID, runID)
	return runID, "", nil
```

- [ ] **Step 7: Wire into SubmitScenarioResult**

At the start of `SubmitScenarioResult` (handlers.go, right after the Phase 0A `[perf]` log added in commit `40761d3`):

```go
	log.Printf("[perf] execution_id=%s result_received_at=%s", raw.RunID, time.Now().UTC().Format(time.RFC3339Nano))
	if err := h.updateExecutionAttemptStatus(r.Context(), raw.RunID, "completed", "completed_at"); err != nil {
		log.Printf("[phase0b] update execution_attempt completed for run %s: %v", raw.RunID, err)
	}
```

- [ ] **Step 8: Wire into ReapStaleRuns (wall-clock timeout)**

In `liveness.go`'s `ReapStaleRuns`, inside the loop that updates `scenario_runs` to `'partial'` (added earlier this session in `ed23b49`):

```go
		if tag.RowsAffected() > 0 {
			h.markVariantRunPartial(ctx, r.id)
			_ = h.updateExecutionAttemptStatus(ctx, r.id, "timed_out", "completed_at")
			log.Printf("[dispatch] run %s on agent %s exceeded wall-clock budget (%s) — marked partial", r.id, r.agentID, staleRunGuard)
		}
```

- [ ] **Step 9: Wire into ReapAbandonedRuns (agent offline)**

In `liveness.go`'s `ReapAbandonedRuns`, the analogous update loop:

```go
		if tag.RowsAffected() > 0 {
			_ = h.updateExecutionAttemptStatus(ctx, a.id, "abandoned", "completed_at")
			log.Printf("[dispatch] run %s on agent %s abandoned (agent offline beyond %s) — marked partial", a.id, a.agentID, abandonedRunGuard)
		}
```

- [ ] **Step 10: Wire into cancelScenarioRun (operator cancel)**

In `handlers.go`'s `cancelScenarioRun`, both branches (agent offline immediate-partial, and the normal grace-period path):

```go
	if !sent {
		_, _ = h.db.Exec(ctx, `UPDATE scenario_runs SET status = 'partial', completed_at = NOW() WHERE id = $1 AND status = 'running'`, runID)
		h.markVariantRunPartial(ctx, runID)
		_ = h.updateExecutionAttemptStatus(ctx, runID, "abandoned", "completed_at")
		return agentID, "partial", nil
	}
	go h.forceCancelAfterGracePeriod(runID, agentID)
	_ = h.updateExecutionAttemptStatus(ctx, runID, "cancelled", "completed_at")
	return agentID, "cancelling", nil
```

- [ ] **Step 11: Run the test to verify it passes**

```bash
cd orchestrator && go test ./internal/api/... -run TestDispatchRun_CreatesExecutionAttemptRow -v
```

Expected: PASS (requires a real Postgres via `TEST_DATABASE_URL`, per this codebase's existing container-backed test convention — see `project_docker_windows` in project memory for local setup)

- [ ] **Step 12: Add the completion-status test**

```go
func TestSubmitScenarioResult_CompletesExecutionAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "run-ea-complete"
		seedRunRow(t, pool, runID, "sc-ea-complete", "agent-ea-complete", "running")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, created_at, dispatch_sent_at)
			 VALUES ('art', 'run', $1, $1, 'dispatched', NOW(), NOW())`, runID); err != nil {
			t.Fatalf("seed execution_attempt: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "sc-ea-complete", AgentID: "agent-ea-complete",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS"}},
		})

		var status string
		if err := pool.QueryRow(context.Background(),
			`SELECT status FROM execution_attempts WHERE source_attempt_id = $1`, runID,
		).Scan(&status); err != nil {
			t.Fatalf("query execution_attempts: %v", err)
		}
		if status != "completed" {
			t.Errorf("status = %q, want completed", status)
		}
	})
}
```

- [ ] **Step 13: Run all Phase 0B API tests**

```bash
cd orchestrator && go test ./internal/api/... -run "TestDispatchRun_CreatesExecutionAttemptRow|TestSubmitScenarioResult_CompletesExecutionAttempt" -v
```

Expected: PASS

- [ ] **Step 14: Build the whole orchestrator to catch any missed call site**

```bash
cd orchestrator && go build ./...
```

Expected: no errors

- [ ] **Step 15: Commit**

```bash
git add internal/api/handlers.go internal/api/liveness.go internal/api/execution_attempt_handlers_test.go
git commit -m "feat(phase0b): ART/Caldera write-side ExecutionAttempt integration"
```

---

## Task 4: Exercise write-side integration

**Files:**
- Modify: `orchestrator/internal/exercise/store.go` — new `UpsertExecutionAttempt` method
- Modify: `orchestrator/internal/exercise/executor.go` — call it alongside existing `UpsertStepExecution` calls
- Create: `orchestrator/internal/exercise/execution_attempt_test.go`

**Interfaces:**
- Consumes: `models.ExecutionAttempt`, `models.ExecutionSourceExercise`, `models.GranularityStep` (Task 2)
- Produces: `Store.UpsertExecutionAttempt(ctx, *models.ExecutionAttempt) error`

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/exercise/execution_attempt_test.go
package exercise

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUpsertExecutionAttempt_InsertsRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		se := &StepExecution{ExecutionID: execID, StepID: "step-1", StepType: StepTypeAgentTask, Status: StepRunning}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if err := store.UpsertExecutionAttempt(ctx, se); err != nil {
			t.Fatalf("UpsertExecutionAttempt: %v", err)
		}

		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM execution_attempts WHERE source_attempt_id = $1`, se.ID,
		).Scan(&status); err != nil {
			t.Fatalf("query execution_attempts: %v", err)
		}
		if status != "running" {
			t.Errorf("status = %q, want running", status)
		}
	})
}

func TestExecutionAttemptStatusFromStepStatus(t *testing.T) {
	cases := []struct {
		in   StepStatus
		want models.ExecutionAttemptStatus
	}{
		{StepPending, models.ExecutionAttemptPending},
		{StepRunning, models.ExecutionAttemptRunning},
		{StepCompleted, models.ExecutionAttemptCompleted},
		{StepCancelled, models.ExecutionAttemptCancelled},
		{StepSkipped, models.ExecutionAttemptSkipped},
	}
	for _, c := range cases {
		got := executionAttemptStatusFromStepStatus(c.in)
		if got != c.want {
			t.Errorf("executionAttemptStatusFromStepStatus(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
```

This uses `seedExecution(t, store)`, an existing helper already defined in `store_test.go:29` (creates a minimal `Plan`+`Execution` pair and returns the execution ID) — reused here rather than duplicated.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/exercise/... -run TestExecutionAttemptStatusFromStepStatus -v
```

Expected: FAIL with "undefined: executionAttemptStatusFromStepStatus"

- [ ] **Step 3: Add the status mapping function and Store method**

In `orchestrator/internal/exercise/store.go`, after the existing `UpsertStepExecution` method:

```go
// executionAttemptStatusFromStepStatus maps internal/exercise's StepStatus
// onto the unified ExecutionAttemptStatus enum. See
// docs/superpowers/specs/2026-09-04-phase0b-execution-attempt-design.md.
func executionAttemptStatusFromStepStatus(s StepStatus) models.ExecutionAttemptStatus {
	switch s {
	case StepPending:
		return models.ExecutionAttemptPending
	case StepRunning:
		return models.ExecutionAttemptRunning
	case StepWaiting:
		return models.ExecutionAttemptRunning // waiting-for-event is still an in-progress attempt
	case StepCompleted:
		return models.ExecutionAttemptCompleted
	case StepFailed:
		return models.ExecutionAttemptCompleted // the step ran; scoring (not this table) judges the outcome
	case StepCancelled:
		return models.ExecutionAttemptCancelled
	case StepSkipped:
		return models.ExecutionAttemptSkipped
	default:
		return models.ExecutionAttemptPending
	}
}

// UpsertExecutionAttempt writes the unified ExecutionAttempt row for one
// StepExecution. source_attempt_id = StepExecution.ID -- accepts the known
// gap (see spec) that a retried step reuses the same ID, since
// UpsertStepExecution itself already collapses retries into one row.
func (s *Store) UpsertExecutionAttempt(ctx context.Context, se *StepExecution) error {
	status := executionAttemptStatusFromStepStatus(se.Status)
	var techniqueID string
	if se.StepType == StepTypeAgentTask {
		// TechniqueID lives on the PlanStep's AgentTaskConfig, not on
		// StepExecution itself -- callers with access to the PlanStep should
		// prefer the richer UpsertExecutionAttemptWithTechnique below; this
		// path is the fallback when only the StepExecution is in scope.
		techniqueID = ""
	}

	if status == models.ExecutionAttemptSkipped {
		_, err := s.db.Exec(ctx,
			`INSERT INTO execution_attempts
				(source, granularity, source_execution_id, source_attempt_id, technique_id, status, skip_reason, created_at, decision_at)
			 VALUES ('exercise', 'step', $1, $2, NULLIF($3, ''), 'skipped', $4, NOW(), NOW())
			 ON CONFLICT (source, source_attempt_id) DO UPDATE
			   SET status = 'skipped', skip_reason = $4, decision_at = NOW()`,
			se.ExecutionID, se.ID, techniqueID, string(models.SkipReasonConditionFalse),
		)
		return err
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO execution_attempts
			(source, granularity, source_execution_id, source_attempt_id, technique_id, status, created_at)
		 VALUES ('exercise', 'step', $1, $2, NULLIF($3, ''), $4, NOW())
		 ON CONFLICT (source, source_attempt_id) DO UPDATE
		   SET status = $4,
		       dispatch_sent_at = CASE WHEN $4 IN ('dispatched','running') AND execution_attempts.dispatch_sent_at IS NULL THEN NOW() ELSE execution_attempts.dispatch_sent_at END,
		       completed_at = CASE WHEN $4 = 'completed' THEN NOW() ELSE execution_attempts.completed_at END`,
		se.ExecutionID, se.ID, techniqueID, string(status),
	)
	return err
}
```

- [ ] **Step 4: Call it alongside UpsertStepExecution in executor.go**

Find every call to `e.store.UpsertStepExecution(...)` in `executor.go` (there are several — in `dispatchStep`, `handleWait`, `handleApproval`, `handleWaitForAgent`, `handleWaitForDetection`, `handleWaitForWebhook`, and the skip/timeout paths in `advance`). After each one, add:

```go
	if err := e.store.UpsertExecutionAttempt(ctx, se); err != nil {
		log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
	}
```

Use the same `ctx` variable already in scope at each call site (some use `ctx`, some use `context.Background()` per the existing code — match whichever the surrounding `UpsertStepExecution` call already uses).

- [ ] **Step 5: Run both tests**

```bash
cd orchestrator && go test ./internal/exercise/... -run "TestExecutionAttemptStatusFromStepStatus|TestUpsertExecutionAttempt_InsertsRow" -v
```

Expected: PASS

- [ ] **Step 6: Build to catch any missed call site**

```bash
cd orchestrator && go build ./...
```

Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add internal/exercise/store.go internal/exercise/executor.go internal/exercise/execution_attempt_test.go
git commit -m "feat(phase0b): exercise engine write-side ExecutionAttempt integration"
```

---

## Task 5: Constraint and idempotency tests

**Files:**
- Modify: `orchestrator/internal/api/execution_attempt_handlers_test.go` (add to the file from Task 3)

**Interfaces:**
- Consumes: nothing new — exercises the schema constraints directly via raw SQL

- [ ] **Step 1: Write the skip-consistency constraint test**

```go
func TestExecutionAttemptsSchema_SkipConsistencyConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()

		// A skipped row WITHOUT skip_reason must be rejected.
		_, err := pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, created_at, decision_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-bad-1', 'skipped', NOW(), NOW())`)
		if err == nil {
			t.Error("expected constraint violation: skipped row without skip_reason")
		}

		// A skipped row WITHOUT decision_at must be rejected.
		_, err = pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, skip_reason, created_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-bad-2', 'skipped', 'condition_false', NOW())`)
		if err == nil {
			t.Error("expected constraint violation: skipped row without decision_at")
		}

		// A non-skipped row WITH skip_reason set must be rejected.
		_, err = pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, skip_reason, created_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-bad-3', 'completed', 'condition_false', NOW())`)
		if err == nil {
			t.Error("expected constraint violation: completed row with skip_reason set")
		}

		// A valid skipped row must succeed.
		_, err = pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, skip_reason, created_at, decision_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-good-1', 'skipped', 'condition_false', NOW(), NOW())`)
		if err != nil {
			t.Errorf("valid skipped row should succeed: %v", err)
		}
	})
}

func TestExecutionAttemptsSchema_IdempotentOnRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		insert := `INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, created_at)
		            VALUES ('art', 'run', 'exec-idem', 'attempt-idem-1', 'pending', NOW())
		            ON CONFLICT (source, source_attempt_id) DO NOTHING`

		if _, err := pool.Exec(ctx, insert); err != nil {
			t.Fatalf("first insert: %v", err)
		}
		if _, err := pool.Exec(ctx, insert); err != nil {
			t.Fatalf("second insert (retry) should not error: %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM execution_attempts WHERE source_attempt_id = 'attempt-idem-1'`,
		).Scan(&count); err != nil {
			t.Fatalf("count query: %v", err)
		}
		if count != 1 {
			t.Errorf("row count = %d, want 1 (retry must not create a duplicate)", count)
		}
	})
}
```

- [ ] **Step 2: Run the constraint tests**

```bash
cd orchestrator && go test ./internal/api/... -run "TestExecutionAttemptsSchema" -v
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/api/execution_attempt_handlers_test.go
git commit -m "test(phase0b): execution_attempts schema constraint and idempotency tests"
```

---

## Task 6: End-to-end integration test

**Files:**
- Modify: `orchestrator/internal/api/execution_attempt_handlers_test.go` (add to the file from Task 3/5)

**Interfaces:**
- Consumes: everything from Tasks 1-5

- [ ] **Step 1: Write the full-lifecycle integration test**

```go
func TestExecutionAttempt_FullLifecycle_DispatchToCompletion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		agentID := "agent-ea-e2e"
		seedActiveAgent(t, pool, agentID, "Linux")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		sc, _ := minimalLiveScenario(t, "int-ea-e2e")
		ctx := context.Background()
		runID, _, err := h.dispatchRun(ctx, sc, agentID, dispatchOpts{Mode: "telemetry", ConfirmLive: true})
		if err != nil {
			t.Fatalf("dispatchRun: %v", err)
		}
		fake.WaitForMessage(t, 2*time.Second)

		// Confirm 'dispatched' status after dispatch.
		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM execution_attempts WHERE source_attempt_id = $1`, runID).Scan(&status); err != nil {
			t.Fatalf("query after dispatch: %v", err)
		}
		if status != "dispatched" {
			t.Fatalf("status after dispatch = %q, want dispatched", status)
		}

		// Agent submits its result.
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS"}},
		})

		// Confirm 'completed' status, and every timestamp column populated
		// through the lifecycle is non-null in the expected order.
		var dispatchQueuedAt, dispatchSentAt, completedAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT dispatch_queued_at, dispatch_sent_at, completed_at FROM execution_attempts WHERE source_attempt_id = $1`,
			runID,
		).Scan(&dispatchQueuedAt, &dispatchSentAt, &completedAt); err != nil {
			t.Fatalf("query after completion: %v", err)
		}
		if dispatchQueuedAt == nil || dispatchSentAt == nil || completedAt == nil {
			t.Fatalf("expected all three timestamps populated, got queued=%v sent=%v completed=%v", dispatchQueuedAt, dispatchSentAt, completedAt)
		}
		if !dispatchQueuedAt.Before(*dispatchSentAt) {
			t.Error("dispatch_queued_at must be before dispatch_sent_at")
		}
		if !dispatchSentAt.Before(*completedAt) {
			t.Error("dispatch_sent_at must be before completed_at")
		}
	})
}
```

- [ ] **Step 2: Run it**

```bash
cd orchestrator && go test ./internal/api/... -run TestExecutionAttempt_FullLifecycle_DispatchToCompletion -v
```

Expected: PASS

- [ ] **Step 3: Run the full API and exercise test suites to confirm no regressions**

```bash
cd orchestrator && go test ./internal/api/... ./internal/exercise/... ./internal/models/... -v 2>&1 | tail -60
```

Expected: PASS (all tests, including every pre-existing test — Phase 0B must not break `scenario_runs`/`exercise_step_executions` behavior)

- [ ] **Step 4: Commit**

```bash
git add internal/api/execution_attempt_handlers_test.go
git commit -m "test(phase0b): end-to-end ExecutionAttempt lifecycle integration test"
```

---

## Summary

**Phase 0B Implementation Complete**

After Task 6:

✅ `execution_attempts` table exists with full constraint set
✅ ART/Caldera runs produce exactly one row, transitioning `pending`→`dispatched`→`completed` (or a terminal failure status via the 4 reaper/cancel paths)
✅ Exercise steps produce a row per `StepExecution`, transitioning through the mapped statuses
✅ Skipped steps produce a `skipped` row with `skip_reason`/`decision_at` populated
✅ Idempotency confirmed — retrying a write does not duplicate rows
✅ No existing behavior changed — purely additive

**Deliverables:**
- Schema (Task 1)
- Go model + constants (Task 2)
- ART/Caldera integration (Task 3)
- Exercise integration (Task 4)
- Constraint/idempotency tests (Task 5)
- End-to-end test (Task 6)

**Not built (explicitly out of scope, per spec):**
- ART/Caldera per-technique streaming (future, needs agent protocol change)
- `internal/exercise`'s retry/attempt-history gap (accepted, separate future work)
- Any Phase 0C consumer of this table (prerequisite evaluation is the next phase)
- Any UI surfacing of this data
