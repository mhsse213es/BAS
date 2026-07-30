# Full Variant Sweep Server-Side Orchestration (Sub-project A: Backend) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the Full Variant Sweep's orchestration (which technique is running, dispatch-the-next-one, track completion) from browser-only JavaScript variables into a DB-persisted, server-ticked job, so a sweep survives page reloads/browser crashes and can always be cancelled.

**Architecture:** A new `vex_sweeps` Postgres table holds one row per sweep (per-agent, race-safe via a partial unique index). A new `internal/vexsweep` package owns a `Store` (CRUD) and a `Dispatcher` that ticks on `exercise.PollScheduler` (the same generic ticker abstraction already used by Global Search's reindex, OpenAEV sync, and the Exercise engine itself), advancing every running sweep one technique at a time regardless of whether any browser is connected. `internal/api` gets 5 new HTTP endpoints plus one new guard on the existing `POST /api/variants/run` handler, both directions of the same-agent conflict rule. This sub-project is backend-only — no frontend changes ship here.

**Tech Stack:** Go, Postgres (pgx), `internal/exercise.PollScheduler` (reused, not rebuilt).

## Global Constraints

- Only one `running` sweep per agent, enforced by a partial unique index (`vex_sweeps (agent_id) WHERE status = 'running'`), not an app-level check-then-insert — must be race-safe under concurrent creates.
- A sweep vs. an ad-hoc `/api/variants/run` on the *same* agent is blocked in both directions (409), with no queueing — conflicting requests are rejected, not deferred.
- `techniques`/`technique_variant_counts` are resolved server-side at sweep creation from the same source `GET /api/art/techniques` uses (`h.artStore.ListTechniqueMeta()`) — never trust a client-submitted technique list.
- Dispatch failure mid-sweep marks the sweep `failed` and stops — it does not silently skip to the next technique (a deliberate change from the current client-side loop's behavior, per the approved spec).
- No new permissions — reuse `auth.CanRunVariants`, `auth.CanViewVariantRun`, `auth.CanCancelScenarioRun` exactly as they gate the existing variant/scenario-run endpoints today.
- No WebSocket push, no frontend changes, no queueing — all explicit non-goals in the spec.

---

### Task 1: `internal/vexsweep` package — `Sweep` model + `Store`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (add the `vex_sweeps` table + partial unique index migration, immediately after the `variant_findings`/`payload_families` block, i.e. after line 553's `idx_variant_findings_run_task` index)
- Create: `orchestrator/internal/vexsweep/sweep.go`
- Create: `orchestrator/internal/vexsweep/store.go`
- Test: `orchestrator/internal/vexsweep/store_test.go`

**Interfaces:**
- Produces: `type Sweep struct { ID, AgentID, Mode string; IncludeAdvanced bool; Techniques []string; TechniqueVariantCounts []int; CurrentIndex int; CurrentVariantRunID, CurrentScenarioRunID string; CompletedVariants, TotalVariants int; Status, Error, CreatedBy string; StartedAt time.Time; CompletedAt *time.Time }`, `type Store struct` (unexported `pool *pgxpool.Pool` field), `func NewStore(pool *pgxpool.Pool) *Store`, `func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error)`, `func (s *Store) Get(ctx context.Context, id string) (Sweep, error)`, `func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error)`, `func (s *Store) ListRunning(ctx context.Context) ([]Sweep, error)`, `func (s *Store) ListByStatus(ctx context.Context, status string) ([]Sweep, error)`, `func (s *Store) AdvanceToNext(ctx context.Context, id string, justCompletedVariants, nextIndex int, nextVariantRunID, nextScenarioRunID string) error`, `func (s *Store) MarkStopped(ctx context.Context, id string) error`, `func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error`, `var ErrAgentAlreadySweeping = errors.New("agent already has a running sweep")` — consumed by Task 2 (Dispatcher) and Task 4 (HTTP handlers).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/vexsweep/store_test.go`:

```go
package vexsweep

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"

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

func TestCreate_PersistsAndGetRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, Sweep{
			AgentID:                "agent-1",
			Mode:                   "sequential",
			Techniques:             []string{"T1059.001", "T1059.003"},
			TechniqueVariantCounts: []int{33, 12},
			TotalVariants:          45,
			CreatedBy:              "user-1",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.ID == "" {
			t.Fatal("Create() returned empty ID")
		}
		if created.Status != "running" {
			t.Errorf("Status = %q, want %q (default)", created.Status, "running")
		}

		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(got.Techniques) != 2 || got.Techniques[0] != "T1059.001" || got.Techniques[1] != "T1059.003" {
			t.Errorf("Techniques = %v, want [T1059.001 T1059.003]", got.Techniques)
		}
		if len(got.TechniqueVariantCounts) != 2 || got.TechniqueVariantCounts[0] != 33 || got.TechniqueVariantCounts[1] != 12 {
			t.Errorf("TechniqueVariantCounts = %v, want [33 12]", got.TechniqueVariantCounts)
		}
		if got.TotalVariants != 45 {
			t.Errorf("TotalVariants = %d, want 45", got.TotalVariants)
		}
	})
}

func TestCreate_RejectsSecondRunningSweepSameAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		base := Sweep{AgentID: "agent-conflict", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1}

		if _, err := store.Create(ctx, base); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		_, err := store.Create(ctx, base)
		if !errors.Is(err, ErrAgentAlreadySweeping) {
			t.Fatalf("second Create() err = %v, want ErrAgentAlreadySweeping", err)
		}
	})
}

func TestCreate_AllowsConcurrentSweepsDifferentAgents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.Create(ctx, Sweep{AgentID: "agent-a", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1}); err != nil {
			t.Fatalf("Create agent-a: %v", err)
		}
		if _, err := store.Create(ctx, Sweep{AgentID: "agent-b", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1}); err != nil {
			t.Fatalf("Create agent-b: %v", err)
		}
		running, err := store.ListRunning(ctx)
		if err != nil {
			t.Fatalf("ListRunning: %v", err)
		}
		if len(running) != 2 {
			t.Fatalf("ListRunning() = %+v, want 2 sweeps (one per agent)", running)
		}
	})
}

func TestGetActiveForAgent_FoundAndNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, Sweep{AgentID: "agent-active", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, found, err := store.GetActiveForAgent(ctx, "agent-active")
		if err != nil {
			t.Fatalf("GetActiveForAgent: %v", err)
		}
		if !found || got.ID != created.ID {
			t.Fatalf("GetActiveForAgent(agent-active) = %+v, found=%v, want ID=%s found=true", got, found, created.ID)
		}
		_, found, err = store.GetActiveForAgent(ctx, "agent-with-no-sweep")
		if err != nil {
			t.Fatalf("GetActiveForAgent: %v", err)
		}
		if found {
			t.Fatal("GetActiveForAgent(agent-with-no-sweep) found=true, want false")
		}
	})
}

func TestAdvanceToNext_CreditsAndAdvancesThenCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, Sweep{
			AgentID: "agent-advance", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		// First technique finishes -- advance to the second.
		if err := store.AdvanceToNext(ctx, created.ID, 33, 1, "vr-2", "sr-2"); err != nil {
			t.Fatalf("AdvanceToNext (1st): %v", err)
		}
		mid, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if mid.CurrentIndex != 1 || mid.CompletedVariants != 33 || mid.CurrentVariantRunID != "vr-2" || mid.Status != "running" {
			t.Fatalf("mid-sweep state = %+v, want CurrentIndex=1 CompletedVariants=33 CurrentVariantRunID=vr-2 Status=running", mid)
		}

		// Second (last) technique finishes -- sweep completes.
		if err := store.AdvanceToNext(ctx, created.ID, 12, 2, "", ""); err != nil {
			t.Fatalf("AdvanceToNext (2nd): %v", err)
		}
		final, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if final.Status != "completed" || final.CompletedVariants != 45 || final.CompletedAt == nil {
			t.Fatalf("final state = %+v, want Status=completed CompletedVariants=45 CompletedAt set", final)
		}
	})
}

func TestMarkStopped_And_MarkFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		stopped, err := store.Create(ctx, Sweep{AgentID: "agent-stop", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkStopped(ctx, stopped.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}
		got, _ := store.Get(ctx, stopped.ID)
		if got.Status != "stopped" || got.CompletedAt == nil {
			t.Fatalf("after MarkStopped: %+v, want Status=stopped CompletedAt set", got)
		}

		failed, err := store.Create(ctx, Sweep{AgentID: "agent-fail", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkFailed(ctx, failed.ID, "agent went offline"); err != nil {
			t.Fatalf("MarkFailed: %v", err)
		}
		got, _ = store.Get(ctx, failed.ID)
		if got.Status != "failed" || got.Error != "agent went offline" {
			t.Fatalf("after MarkFailed: %+v, want Status=failed Error=%q", got, "agent went offline")
		}
	})
}
```

Add `"github.com/jackc/pgx/v5/pgxpool"` to the import block (needed for the `pool *pgxpool.Pool` parameter in each `RunWithPool` closure).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/vexsweep/... 2>&1`
Expected: FAIL — the package doesn't exist yet (`no Go files in ...`).

- [ ] **Step 3: Add the `vex_sweeps` migration**

In `orchestrator/internal/db/postgres.go`, immediately after the line `` `CREATE UNIQUE INDEX IF NOT EXISTS idx_variant_findings_run_task ON variant_findings (variant_run_id, task_id)`, `` (the line right after the `payload_families` comment begins — insert *before* the `payload_families` table, directly after that unique index line), add:

```go
		// vex_sweeps: server-owned Full Variant Sweep orchestration state.
		// One row per sweep; the partial unique index below makes "one
		// running sweep per agent" race-safe (not an app-level
		// check-then-insert) -- two simultaneous creates for the same
		// agent can never both succeed. See
		// docs/superpowers/specs/2026-07-30-vex-full-sweep-server-orchestration-design.md.
		`CREATE TABLE IF NOT EXISTS vex_sweeps (
			id                       text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id                 text        NOT NULL,
			mode                     text        NOT NULL DEFAULT 'sequential',
			include_advanced         boolean     NOT NULL DEFAULT false,
			techniques               text[]      NOT NULL,
			technique_variant_counts int[]       NOT NULL,
			current_index            int         NOT NULL DEFAULT 0,
			current_variant_run_id   text        NOT NULL DEFAULT '',
			current_scenario_run_id  text        NOT NULL DEFAULT '',
			completed_variants       int         NOT NULL DEFAULT 0,
			total_variants           int         NOT NULL DEFAULT 0,
			status                   text        NOT NULL DEFAULT 'running',
			error                    text        NOT NULL DEFAULT '',
			created_by               text        NOT NULL DEFAULT '',
			started_at               timestamptz NOT NULL DEFAULT NOW(),
			completed_at             timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vex_sweeps_agent ON vex_sweeps (agent_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_sweeps_one_running_per_agent
			ON vex_sweeps (agent_id) WHERE status = 'running'`,
```

- [ ] **Step 4: Implement `Sweep` and `Store`**

Create `orchestrator/internal/vexsweep/sweep.go`:

```go
// Package vexsweep owns server-side orchestration of the Full Variant
// Sweep feature -- dispatching every ART technique for an agent
// sequentially, tracking progress, and surviving browser reloads/crashes.
// See docs/superpowers/specs/2026-07-30-vex-full-sweep-server-orchestration-design.md.
package vexsweep

import "time"

// Sweep is one Full Variant Sweep's persisted state.
type Sweep struct {
	ID                     string
	AgentID                string
	Mode                   string
	IncludeAdvanced        bool
	Techniques             []string
	TechniqueVariantCounts []int
	CurrentIndex           int
	CurrentVariantRunID    string
	CurrentScenarioRunID   string
	CompletedVariants      int
	TotalVariants          int
	Status                 string
	Error                  string
	CreatedBy              string
	StartedAt              time.Time
	CompletedAt            *time.Time
}
```

Create `orchestrator/internal/vexsweep/store.go`:

```go
package vexsweep

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAgentAlreadySweeping is returned by Create when the partial unique
// index rejects a second running sweep for the same agent.
var ErrAgentAlreadySweeping = errors.New("agent already has a running sweep")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const sweepCols = `id, agent_id, mode, include_advanced, techniques, technique_variant_counts,
	current_index, current_variant_run_id, current_scenario_run_id,
	completed_variants, total_variants, status, error, created_by, started_at, completed_at`

func scanSweep(row interface {
	Scan(dest ...any) error
}) (Sweep, error) {
	var sw Sweep
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Mode, &sw.IncludeAdvanced, &sw.Techniques, &sw.TechniqueVariantCounts,
		&sw.CurrentIndex, &sw.CurrentVariantRunID, &sw.CurrentScenarioRunID,
		&sw.CompletedVariants, &sw.TotalVariants, &sw.Status, &sw.Error, &sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt)
	return sw, err
}

func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO vex_sweeps (agent_id, mode, include_advanced, techniques, technique_variant_counts, total_variants, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING `+sweepCols,
		sw.AgentID, sw.Mode, sw.IncludeAdvanced, sw.Techniques, sw.TechniqueVariantCounts, sw.TotalVariants, sw.CreatedBy)
	created, err := scanSweep(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Sweep{}, ErrAgentAlreadySweeping
		}
		return Sweep{}, err
	}
	return created, nil
}

func (s *Store) Get(ctx context.Context, id string) (Sweep, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+sweepCols+` FROM vex_sweeps WHERE id = $1`, id)
	return scanSweep(row)
}

func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+sweepCols+` FROM vex_sweeps WHERE agent_id = $1 AND status = 'running'`, agentID)
	sw, err := scanSweep(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Sweep{}, false, nil
		}
		return Sweep{}, false, err
	}
	return sw, true, nil
}

func (s *Store) ListRunning(ctx context.Context) ([]Sweep, error) {
	return s.ListByStatus(ctx, "running")
}

func (s *Store) ListByStatus(ctx context.Context, status string) ([]Sweep, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sweepCols+` FROM vex_sweeps WHERE status = $1 ORDER BY started_at`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sweep
	for rows.Next() {
		sw, err := scanSweep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rows.Err()
}

// AdvanceToNext credits justCompletedVariants to completed_variants, sets
// current_index to the caller-computed nextIndex (NOT current_index+1 --
// the caller already knows the correct next index: unchanged for a sweep's
// very first dispatch, current+1 only when advancing past an
// already-dispatched technique), and records the new current run IDs (both
// empty strings mean "no next technique" -- the sweep is marked completed
// instead). Called by the Dispatcher (Task 2) once per finished technique.
func (s *Store) AdvanceToNext(ctx context.Context, id string, justCompletedVariants, nextIndex int, nextVariantRunID, nextScenarioRunID string) error {
	if nextVariantRunID == "" && nextScenarioRunID == "" {
		_, err := s.pool.Exec(ctx,
			`UPDATE vex_sweeps
			    SET completed_variants = completed_variants + $2,
			        current_index = $3,
			        current_variant_run_id = '', current_scenario_run_id = '',
			        status = 'completed', completed_at = NOW()
			  WHERE id = $1`,
			id, justCompletedVariants, nextIndex)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps
		    SET completed_variants = completed_variants + $2,
		        current_index = $3,
		        current_variant_run_id = $4, current_scenario_run_id = $5
		  WHERE id = $1`,
		id, justCompletedVariants, nextIndex, nextVariantRunID, nextScenarioRunID)
	return err
}

func (s *Store) MarkStopped(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps SET status = 'stopped', completed_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps SET status = 'failed', error = $2, completed_at = NOW() WHERE id = $1`, id, errMsg)
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/vexsweep/... -v`
Expected: build succeeds; all 6 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/vexsweep/
git commit -m "feat(vexsweep): add vex_sweeps table and Store (per-agent sweep persistence)"
git push
```

---

### Task 2: `Dispatcher` — tick-driven sequential advancement

**Files:**
- Create: `orchestrator/internal/vexsweep/dispatcher.go`
- Test: `orchestrator/internal/vexsweep/dispatcher_test.go`

**Interfaces:**
- Consumes: `Store` (Task 1) — `ListRunning`, `AdvanceToNext`, `MarkFailed`.
- Produces: `type DispatchFn func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)`, `type VariantRunStatusFn func(ctx context.Context, variantRunID string) (status string, err error)`, `type Dispatcher struct` (unexported fields), `func NewDispatcher(store *Store, statusFn VariantRunStatusFn) *Dispatcher`, `func (d *Dispatcher) SetDispatch(fn DispatchFn)`, `func (d *Dispatcher) Tick(ctx context.Context) error` (exported so tests can call it directly without a real ticker), `func (d *Dispatcher) Start(scheduler interface{ Start(func(context.Context)) })`, `func (d *Dispatcher) Stop(scheduler interface{ Stop() })` — consumed by Task 6 (`main.go` wiring, where the scheduler is a real `*exercise.PollScheduler`).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/vexsweep/dispatcher_test.go`:

```go
package vexsweep

import (
	"context"
	"errors"
	"testing"
)

func TestDispatcher_Tick_DispatchesFirstTechniqueForNewSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-1", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		var dispatchedTechniques []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil // nothing has "completed" yet in this test
		})
		d.SetDispatch(func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			dispatchedTechniques = append(dispatchedTechniques, techniqueID)
			return "sr-1", "vr-1", 33, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedTechniques) != 1 || dispatchedTechniques[0] != "T1059.001" {
			t.Fatalf("dispatchedTechniques = %v, want [T1059.001]", dispatchedTechniques)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.CurrentVariantRunID != "vr-1" || got.CurrentScenarioRunID != "sr-1" {
			t.Fatalf("after first tick: %+v, want CurrentVariantRunID=vr-1 CurrentScenarioRunID=sr-1", got)
		}
	})
}

func TestDispatcher_Tick_AdvancesWhenCurrentTechniqueFinishes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-2", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-1", "sr-1"); err != nil {
			// Simulate: dispatcher already dispatched technique 1 (index 0)
			// on a prior tick -- nextIndex=0 since this was the sweep's
			// first-ever dispatch, index unchanged from its starting value.
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var dispatchedTechniques []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			if variantRunID == "vr-1" {
				return "completed", nil
			}
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			dispatchedTechniques = append(dispatchedTechniques, techniqueID)
			return "sr-2", "vr-2", 12, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedTechniques) != 1 || dispatchedTechniques[0] != "T1059.003" {
			t.Fatalf("dispatchedTechniques = %v, want [T1059.003]", dispatchedTechniques)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.CompletedVariants != 33 || got.CurrentIndex != 1 {
			t.Fatalf("after advancing: %+v, want CompletedVariants=33 CurrentIndex=1", got)
		}
	})
}

func TestDispatcher_Tick_CompletesSweepAfterLastTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-3", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-1", "sr-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "completed", nil
		})
		d.SetDispatch(func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			t.Fatal("dispatch should not be called -- no techniques remain after the last one")
			return "", "", 0, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "completed" || got.CompletedVariants != 33 {
			t.Fatalf("after last tick: %+v, want Status=completed CompletedVariants=33", got)
		}
	})
}

func TestDispatcher_Tick_MarksFailedOnDispatchError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-4", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			return "", "", 0, errors.New("agent not connected")
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick itself should not error (failure is recorded on the sweep, not returned): %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "failed" || got.Error != "agent not connected" {
			t.Fatalf("after dispatch error: %+v, want Status=failed Error=%q", got, "agent not connected")
		}
	})
}

func TestDispatcher_Tick_IgnoresStoppedAndFailedSweeps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-5", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkStopped(ctx, sw.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			t.Fatal("status check should not be called for a stopped sweep")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			t.Fatal("dispatch should not be called for a stopped sweep")
			return "", "", 0, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/vexsweep/... 2>&1`
Expected: FAIL — `undefined: NewDispatcher`.

- [ ] **Step 3: Implement `Dispatcher`**

Create `orchestrator/internal/vexsweep/dispatcher.go`:

```go
package vexsweep

import (
	"context"
	"log"
)

// DispatchFn dispatches one technique's variants to an agent. Injected
// after construction (SetDispatch) to avoid an internal/vexsweep ->
// internal/api import cycle -- the same pattern internal/exercise.Executor
// already uses for its AgentDispatchFn.
type DispatchFn func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)

// VariantRunStatusFn reports a variant run's current status
// ("running"/"completed"/"failed"/"partial"), read directly from
// variant_runs/scenario_runs -- no callback into internal/api needed for
// this half, since it's a plain read of tables vexsweep can query itself.
type VariantRunStatusFn func(ctx context.Context, variantRunID string) (status string, err error)

type Dispatcher struct {
	store    *Store
	status   VariantRunStatusFn
	dispatch DispatchFn
}

func NewDispatcher(store *Store, status VariantRunStatusFn) *Dispatcher {
	return &Dispatcher{store: store, status: status}
}

func (d *Dispatcher) SetDispatch(fn DispatchFn) { d.dispatch = fn }

// Tick advances every running sweep by at most one step. Exported so tests
// can call it directly without a real ticker; production wiring (Task 6)
// calls it from an exercise.PollScheduler tick callback.
func (d *Dispatcher) Tick(ctx context.Context) error {
	sweeps, err := d.store.ListRunning(ctx)
	if err != nil {
		return err
	}
	for _, sw := range sweeps {
		d.advance(ctx, sw)
	}
	return nil
}

func (d *Dispatcher) advance(ctx context.Context, sw Sweep) {
	if sw.CurrentVariantRunID != "" {
		status, err := d.status(ctx, sw.CurrentVariantRunID)
		if err != nil {
			log.Printf("[vexsweep] status check failed for sweep %s variant_run %s: %v", sw.ID, sw.CurrentVariantRunID, err)
			return
		}
		if status == "running" {
			return // nothing to do this tick
		}
		// Technique finished (completed/failed/partial) -- credit its variants.
		d.dispatchNext(ctx, sw, sw.TechniqueVariantCounts[sw.CurrentIndex])
		return
	}
	// No technique in flight yet -- this is the sweep's very first tick.
	d.dispatchNext(ctx, sw, 0)
}

func (d *Dispatcher) dispatchNext(ctx context.Context, sw Sweep, justFinishedCount int) {
	nextIdx := sw.CurrentIndex
	if sw.CurrentVariantRunID != "" {
		nextIdx = sw.CurrentIndex + 1
	}
	if nextIdx >= len(sw.Techniques) {
		if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, "", ""); err != nil {
			log.Printf("[vexsweep] complete sweep %s: %v", sw.ID, err)
		}
		return
	}

	scenarioRunID, variantRunID, _, err := d.dispatch(ctx, sw.AgentID, sw.Techniques[nextIdx], sw.Mode, sw.IncludeAdvanced)
	if err != nil {
		// Deliberately does not fall through to the next technique -- a
		// silently-skipped technique in a security-validation sweep is
		// worse than a sweep that stops and says why. See design spec
		// Architecture §2.
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[vexsweep] mark sweep %s failed: %v", sw.ID, merr)
		}
		return
	}
	if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, variantRunID, scenarioRunID); err != nil {
		log.Printf("[vexsweep] advance sweep %s: %v", sw.ID, err)
	}
}
```

Note: `AdvanceToNext` takes `nextIdx` explicitly rather than incrementing `current_index` itself, because the correct next index depends on which case `dispatchNext` is in: unchanged (`sw.CurrentIndex`) for a sweep's very first dispatch (no technique was in flight before, so there's nothing to advance past), or `sw.CurrentIndex + 1` when a previously-dispatched technique just finished. A blind `current_index + 1` inside the Store would double-increment the first-dispatch case — this was caught as a real bug during Task 2 implementation (a real Postgres-backed test run panicked with an out-of-range index once `TestDispatcher_Tick_CompletesSweepAfterLastTechnique` exercised a single-technique sweep end to end) and fixed by moving index computation entirely into the Dispatcher, with the Store trusting whatever `nextIndex` it's given.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/vexsweep/... -v`
Expected: build succeeds; all 11 tests (6 from Task 1 + 5 new) PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/vexsweep/dispatcher.go orchestrator/internal/vexsweep/dispatcher_test.go
git commit -m "feat(vexsweep): add tick-driven Dispatcher (advance-on-completion, fail-not-skip)"
git push
```

---

### Task 3: `Handler.dispatchVariantForSweep` + `Handler.WithVexSweep`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (add a `vexSweep *vexsweep.Store` field near the existing `rules *rulelib.Engine` field around line 90, add `WithVexSweep` near `WithRuleLibrary` around line 241)
- Modify: `orchestrator/internal/api/variant_handlers.go` (add `dispatchVariantForSweep`, after `dispatchVariantRun`)
- Test: `orchestrator/internal/api/variant_handlers_test.go` (create if it doesn't already exist, or append if it does — check first)

**Interfaces:**
- Consumes: `h.resolveTemplates` and `h.dispatchVariantRun` (existing, `internal/api/variant_handlers.go`); `vexsweep.Store` (Task 1).
- Produces: `func (h *Handler) dispatchVariantForSweep(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)` — matches `vexsweep.DispatchFn`'s exact signature, consumed by Task 6's `main.go` wiring (`vexSweepDispatcher.SetDispatch(handler.dispatchVariantForSweep)`). `func (h *Handler) WithVexSweep(store *vexsweep.Store) *Handler` — consumed by Task 4 (handlers read `h.vexSweep`) and Task 6 (`main.go`'s `.WithVexSweep(...)` chain call).

- [ ] **Step 1: Check whether `variant_handlers_test.go` exists**

Run: `cd orchestrator && ls internal/api/variant_handlers_test.go 2>&1`

If it exists, read it first to match its existing style before appending. If not, the test file is created fresh in the next step.

- [ ] **Step 2: Write the failing test**

Add to `orchestrator/internal/api/variant_handlers_test.go` (create the file with this content if it didn't already exist; otherwise append this function and add any missing imports from the block below):

```go
package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
)

func TestDispatchVariantForSweep_NoARTStoreReturnsError(t *testing.T) {
	// h.artStore is nil in this bare Handler (no WithART/WithContentSeed
	// called) -- resolveTemplates' ART-fallback path must surface a clear
	// error, not panic, so the dispatcher can mark the sweep failed cleanly.
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	_, _, _, err := h.dispatchVariantForSweep(context.Background(), "agent-1", "T1059.001", "sequential", false)
	if err == nil {
		t.Fatal("dispatchVariantForSweep() with no ART store loaded, want an error, got nil")
	}
}

func TestHandler_WithVexSweep_StoresReference(t *testing.T) {
	store := vexsweep.NewStore(nil)
	h := New(nil, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store)
	if h.vexSweep != store {
		t.Fatal("WithVexSweep did not store the given *vexsweep.Store on the Handler")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/api/... 2>&1`
Expected: FAIL — `h.dispatchVariantForSweep undefined` and `h.WithVexSweep undefined` / `h.vexSweep undefined`.

- [ ] **Step 4: Add the `vexSweep` field and `WithVexSweep`**

In `orchestrator/internal/api/handlers.go`, add `"github.com/audspect/bas/internal/vexsweep"` to the import block. Near the existing field `rules *rulelib.Engine // nil when not loaded — Detection Rule Library` (around line 90), add:

```go
	vexSweep *vexsweep.Store // nil when not loaded — Full Variant Sweep orchestration
```

Immediately after the existing `WithRuleLibrary` method (around line 244, right after its closing `}`), add:

```go
// WithVexSweep attaches the Full Variant Sweep store.
func (h *Handler) WithVexSweep(store *vexsweep.Store) *Handler {
	h.vexSweep = store
	return h
}
```

- [ ] **Step 5: Add `dispatchVariantForSweep`**

In `orchestrator/internal/api/variant_handlers.go`, immediately after the existing `dispatchVariantRun` function (ends around line 620, right after `return scenarioRunID, variantRunID, nil` and its closing `}`), add:

```go
// dispatchVariantForSweep is the vexsweep.DispatchFn implementation --
// resolves templates and dispatches exactly like RunVariants does for a
// single ad-hoc request, but returns the resolved variant count too so the
// Dispatcher can credit the sweep's real (not precomputed) total.
func (h *Handler) dispatchVariantForSweep(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error) {
	templates, baseID, err := h.resolveTemplates(ctx, techniqueID, "art", "", "", "", includeAdvanced)
	if err != nil {
		return "", "", 0, err
	}
	if len(templates) == 0 {
		return "", "", 0, fmt.Errorf("no variants generated for %s", techniqueID)
	}
	scenarioRunID, variantRunID, err = h.dispatchVariantRun(ctx, agentID, techniqueID, "art", baseID, mode, templates)
	if err != nil {
		return "", "", 0, err
	}
	return scenarioRunID, variantRunID, len(templates), nil
}
```

`fmt` is already imported in `variant_handlers.go` — no new import needed there.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestDispatchVariantForSweep_NoARTStoreReturnsError|TestHandler_WithVexSweep_StoresReference' -v`
Expected: build succeeds; both tests PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/variant_handlers.go orchestrator/internal/api/variant_handlers_test.go
git commit -m "feat(api): add dispatchVariantForSweep and WithVexSweep(store)"
git push
```

---

### Task 4: Sweep HTTP endpoints + shared cancel helper

**Files:**
- Create: `orchestrator/internal/api/vexsweep_handlers.go`
- Modify: `orchestrator/internal/api/handlers.go` (factor `CancelRun`'s cancellation logic, currently lines 2099-2130, into a shared helper `cancelScenarioRun`)
- Modify: `orchestrator/internal/api/routes.go` (register 5 new routes, near the existing variant routes at line 293-298)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (5 new `routeMatrix` entries)
- Test: `orchestrator/internal/api/vexsweep_handlers_test.go`

**Interfaces:**
- Consumes: `h.vexSweep *vexsweep.Store` (Task 3); `vexsweep.Sweep`, `vexsweep.ErrAgentAlreadySweeping` (Task 1); `h.artStore.ListTechniqueMeta() []scenario.TechniqueMeta` (existing, `internal/api/handlers.go:3434`); `h.resolveTemplates` (existing, used to compute each technique's variant count at creation time).
- Produces: `func (h *Handler) CreateVexSweep`, `func (h *Handler) GetActiveVexSweep`, `func (h *Handler) GetVexSweep`, `func (h *Handler) ListVexSweeps`, `func (h *Handler) CancelVexSweep` (all `http.HandlerFunc`-shaped) — registered in `routes.go`, no other package consumes these directly.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/vexsweep_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateVexSweep_RejectsWhenNoARTStoreLoaded(t *testing.T) {
	// No WithART/WithContentSeed called -- artStore is nil, so the handler
	// cannot resolve a technique list and must fail cleanly, not panic.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool))
		userID := seedUser(t, pool, "sweep-create-user", "password123", "admin", true)
		body, _ := json.Marshal(map[string]string{"agentId": "agent-1", "mode": "sequential"})
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps", bytes.NewReader(body), auth.RoleAdmin, userID)
		rec := callAuthed(h.CreateVexSweep, req)
		if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want a server error (ART store not loaded), body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateVexSweep_RejectsWhenAgentHasRunningVariantRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO variant_runs (id, agent_id, technique_id, scenario_run_id, total_variants, status)
			 VALUES ('vr-conflict-1', 'agent-conflict', 'T1059.001', 'sr-conflict-1', 33, 'running')`); err != nil {
			t.Fatalf("seed running variant_run: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool))
		userID := seedUser(t, pool, "sweep-conflict-user", "password123", "admin", true)
		body, _ := json.Marshal(map[string]string{"agentId": "agent-conflict", "mode": "sequential"})
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps", bytes.NewReader(body), auth.RoleAdmin, userID)
		rec := callAuthed(h.CreateVexSweep, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetActiveVexSweep_404WhenNoneRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool))
		userID := seedUser(t, pool, "sweep-active-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/active?agentId=agent-no-sweep", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.GetActiveVexSweep, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetActiveVexSweep_ReturnsRunningSweepWithLiveCompletedVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-live-progress", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{2, 12}, TotalVariants: 14,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-live-1", "sr-live-1"); err != nil {
			t.Fatalf("AdvanceToNext: %v", err)
		}
		// Simulate 1 of the 2 in-flight technique's variants having a
		// recorded result already -- results is a jsonb array on
		// scenario_runs, one entry per completed step.
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-live-1', '__variant__t1059.001', 'agent-live-progress', 'test', 'running', '[{"id":"step1"}]', 2)`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store)
		userID := seedUser(t, pool, "sweep-live-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/active?agentId=agent-live-progress", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.GetActiveVexSweep, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got struct {
			CompletedVariants int `json:"completedVariants"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// 0 (no prior technique finished yet) + 1 (in-flight technique's
		// one recorded step result) = 1.
		if got.CompletedVariants != 1 {
			t.Fatalf("completedVariants = %d, want 1 (live, includes in-flight technique's finished steps)", got.CompletedVariants)
		}
	})
}

func TestCancelVexSweep_StopsSweepAndCancelsCurrentRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-cancel", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-cancel-1", "sr-cancel-1"); err != nil {
			t.Fatalf("AdvanceToNext: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-cancel-1', '__variant__t1059.001', 'agent-cancel', 'test', 'running', '[]', 33)`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store)
		userID := seedUser(t, pool, "sweep-cancel-user", "password123", "admin", true)
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps/"+sw.ID+"/cancel", nil, auth.RoleAdmin, userID)
		req = mux(req, "id", sw.ID)
		rec := callAuthed(h.CancelVexSweep, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		got, err := store.Get(ctx, sw.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != "stopped" {
			t.Errorf("Status = %q, want %q", got.Status, "stopped")
		}
		var runStatus string
		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'sr-cancel-1'`).Scan(&runStatus); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if runStatus != "partial" {
			t.Errorf("scenario_runs.status = %q, want %q (agent offline in this test, so cancel marks it partial immediately)", runStatus, "partial")
		}
	})
}

// mux injects a chi URL param into req's context the same way chi's router
// would after matching "/api/vex/sweeps/{id}/cancel" -- needed because
// these tests call the handler directly, bypassing the real router.
func mux(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}
```

Check whether a `mux`-shaped test helper already exists elsewhere in `internal/api`'s test files before adding this one (grep for `chi.NewRouteContext` in `*_test.go`) — if an equivalent helper already exists under a different name, reuse it and delete this duplicate instead of introducing a second one.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/api/... 2>&1`
Expected: FAIL — `h.CreateVexSweep undefined`, `h.GetActiveVexSweep undefined`, `h.CancelVexSweep undefined`.

- [ ] **Step 3: Factor `CancelRun`'s logic into a shared helper**

In `orchestrator/internal/api/handlers.go`, replace the body of `CancelRun` (currently lines 2099-2130ish) with a call to a new shared helper, keeping `CancelRun`'s own HTTP-specific bits (reading the URL param, writing the response) separate from the reusable cancellation logic:

```go
func (h *Handler) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	status, err := h.cancelScenarioRun(r.Context(), runID)
	if err != nil {
		if err == errRunNotFound {
			jsonError(w, "run not found", http.StatusNotFound)
			return
		}
		if err == errRunNotRunning {
			jsonError(w, "run is not running (status: "+status+")", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "scenario.cancel", runID, map[string]any{"outcome": status}, "ok")
	respond(w, map[string]string{"runId": runID, "status": status})
}

var errRunNotFound = fmt.Errorf("run not found")
var errRunNotRunning = fmt.Errorf("run not running")

// cancelScenarioRun cancels an in-flight scenario_run -- notifies the agent
// to stop gracefully (completed steps kept, run marked partial), or marks
// it partial immediately if the agent is offline. Shared by CancelRun
// (direct API) and CancelVexSweep (cancelling a sweep's in-flight
// technique run).
func (h *Handler) cancelScenarioRun(ctx context.Context, runID string) (status string, err error) {
	var agentID string
	if err := h.db.QueryRow(ctx,
		`SELECT agent_id, status FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &status); err != nil {
		return "", errRunNotFound
	}
	if status != "running" {
		return status, errRunNotRunning
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandCancel,
		AgentID: agentID,
		Data:    map[string]string{"runId": runID},
	})
	if !sent {
		_, _ = h.db.Exec(ctx,
			`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
			  WHERE id = $1 AND status = 'running'`, runID)
		log.Printf("[scenario] cancel run %s — agent %s offline, marked partial", runID, agentID)
		return "partial", nil
	}
	log.Printf("[scenario] cancel requested for run %s → agent %s", runID, agentID)
	return "stopping", nil
}
```

Check `handlers.go`'s existing imports already include `fmt`, `log`, and `models` (they do, per the original `CancelRun` body) — no new imports needed for this step.

- [ ] **Step 4: Implement the 5 sweep handlers**

Create `orchestrator/internal/api/vexsweep_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/vexsweep"
)

// POST /api/vex/sweeps
// Creates a new Full Variant Sweep. Techniques are resolved server-side
// from the ART catalog -- never trusts a client-submitted list. Rejects
// (409) if the agent already has a running sweep, or a running ad-hoc
// variant run (the two directions of the same-agent conflict rule; see
// design spec Architecture §3).
func (h *Handler) CreateVexSweep(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID         string `json:"agentId"`
		Mode            string `json:"mode"`
		IncludeAdvanced bool   `json:"includeAdvanced"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	if h.artStore == nil {
		jsonError(w, "ART content not loaded", http.StatusServiceUnavailable)
		return
	}
	mode := coalesce(req.Mode, "sequential")
	ctx := r.Context()

	var runningVariantRunID string
	if err := h.db.QueryRow(ctx,
		`SELECT id FROM variant_runs WHERE agent_id = $1 AND status = 'running' LIMIT 1`, req.AgentID,
	).Scan(&runningVariantRunID); err == nil {
		jsonError(w, "agent has an active variant run — stop it before starting a sweep", http.StatusConflict)
		return
	}

	metas := h.artStore.ListTechniqueMeta()
	techniques := make([]string, 0, len(metas))
	counts := make([]int, 0, len(metas))
	total := 0
	for _, m := range metas {
		templates, _, err := h.resolveTemplates(ctx, m.ID, "art", "", "", "", req.IncludeAdvanced)
		if err != nil || len(templates) == 0 {
			continue // matches vexRunFullSweep's own behavior of skipping techniques with no generated variants
		}
		techniques = append(techniques, m.ID)
		counts = append(counts, len(templates))
		total += len(templates)
	}
	if len(techniques) == 0 {
		jsonError(w, "no techniques with generatable variants found", http.StatusUnprocessableEntity)
		return
	}

	c, _ := auth.ClaimsFrom(ctx)
	createdBy := ""
	if c != nil {
		createdBy = c.UserID
	}

	sw, err := h.vexSweep.Create(ctx, vexsweep.Sweep{
		AgentID: req.AgentID, Mode: mode, IncludeAdvanced: req.IncludeAdvanced,
		Techniques: techniques, TechniqueVariantCounts: counts, TotalVariants: total, CreatedBy: createdBy,
	})
	if err != nil {
		if err == vexsweep.ErrAgentAlreadySweeping {
			jsonError(w, "agent already has a running sweep", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "vexsweep.create", sw.ID, map[string]any{"agentId": req.AgentID, "totalVariants": total, "techniqueCount": len(techniques)}, "ok")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, sweepToJSON(h.db, sw))
}

// GET /api/vex/sweeps/active?agentId=X
func (h *Handler) GetActiveVexSweep(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	sw, found, err := h.vexSweep.GetActiveForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "no active sweep for this agent", http.StatusNotFound)
		return
	}
	jsonOK(w, sweepToJSON(h.db, sw))
}

// GET /api/vex/sweeps/{id}
func (h *Handler) GetVexSweep(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sw, err := h.vexSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}
	jsonOK(w, sweepToJSON(h.db, sw))
}

// GET /api/vex/sweeps?status=running
func (h *Handler) ListVexSweeps(w http.ResponseWriter, r *http.Request) {
	status := coalesce(strings.TrimSpace(r.URL.Query().Get("status")), "running")
	sweeps, err := h.vexSweep.ListByStatus(r.Context(), status)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(sweeps))
	for _, sw := range sweeps {
		out = append(out, sweepToJSON(h.db, sw))
	}
	jsonOK(w, out)
}

// POST /api/vex/sweeps/{id}/cancel
func (h *Handler) CancelVexSweep(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	sw, err := h.vexSweep.Get(ctx, id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}
	if sw.Status != "running" {
		jsonError(w, "sweep is not running (status: "+sw.Status+")", http.StatusConflict)
		return
	}
	if sw.CurrentScenarioRunID != "" {
		if _, err := h.cancelScenarioRun(ctx, sw.CurrentScenarioRunID); err != nil && err != errRunNotRunning {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := h.vexSweep.MarkStopped(ctx, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "vexsweep.cancel", id, map[string]any{"agentId": sw.AgentID}, "ok")
	jsonOK(w, map[string]string{"id": id, "status": "stopped"})
}

// sweepToJSON serializes a Sweep plus a live-computed completedVariants
// that includes the in-flight technique's already-finished steps (read
// from scenario_runs.results' array length) -- not just the last fully
// completed technique's tally that Sweep.CompletedVariants alone holds.
// See design spec Architecture §4.
func sweepToJSON(db *pgxpool.Pool, sw vexsweep.Sweep) map[string]any {
	live := sw.CompletedVariants
	if sw.CurrentScenarioRunID != "" {
		var n int
		if err := db.QueryRow(context.Background(),
			`SELECT COALESCE(jsonb_array_length(results), 0) FROM scenario_runs WHERE id = $1`,
			sw.CurrentScenarioRunID,
		).Scan(&n); err == nil {
			live += n
		}
	}
	return map[string]any{
		"id": sw.ID, "agentId": sw.AgentID, "mode": sw.Mode, "includeAdvanced": sw.IncludeAdvanced,
		"techniques": sw.Techniques, "currentIndex": sw.CurrentIndex,
		"currentTechnique": currentTechnique(sw), "currentVariantRunId": sw.CurrentVariantRunID,
		"currentScenarioRunId": sw.CurrentScenarioRunID, "completedVariants": live,
		"totalVariants": sw.TotalVariants, "totalTechniques": len(sw.Techniques),
		"status": sw.Status, "error": sw.Error, "createdBy": sw.CreatedBy,
		"startedAt": sw.StartedAt, "completedAt": sw.CompletedAt,
	}
}

func currentTechnique(sw vexsweep.Sweep) string {
	if sw.CurrentIndex >= 0 && sw.CurrentIndex < len(sw.Techniques) {
		return sw.Techniques[sw.CurrentIndex]
	}
	return ""
}
```

Add `"context"` and `"github.com/jackc/pgx/v5/pgxpool"` to this file's imports (needed for `sweepToJSON`'s `context.Background()` call and its `*pgxpool.Pool` parameter — matching `h.db`'s real type, which is a `*pgxpool.Pool` in both production and tests via `sharedDB.RunWithPool`).

- [ ] **Step 5: Register routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing line `r.With(auth.RequirePermission(auth.CanViewVariantStats)).Get("/api/variants/stats", h.GetVariantStats)` (line 298), add:

```go
		r.With(auth.RequirePermission(auth.CanRunVariants)).Post("/api/vex/sweeps", h.CreateVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/active", h.GetActiveVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}", h.GetVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps", h.ListVexSweeps)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/vex/sweeps/{id}/cancel", h.CancelVexSweep)
```

- [ ] **Step 6: Add the same-agent conflict guard to the existing `RunVariants` handler**

In `orchestrator/internal/api/variant_handlers.go`, in `RunVariants` (currently starts around line 70), immediately after the existing validation `if req.AgentID == "" || req.TechniqueID == "" { ... }` block, add:

```go
	if h.vexSweep != nil {
		if _, found, err := h.vexSweep.GetActiveForAgent(r.Context(), req.AgentID); err == nil && found {
			jsonError(w, "agent has an active Full Sweep — stop it before running an individual variant test", http.StatusConflict)
			return
		}
	}
```

(`h.vexSweep != nil` guards the case where a test or older deployment never calls `WithVexSweep` — matches the nil-safe pattern every other optional `Handler` field already uses.)

- [ ] **Step 7: Add RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing line `{http.MethodGet, "/api/variants/stats", tierPermission, auth.CanViewVariantStats},` (near line 184), add:

```go
		{http.MethodPost, "/api/vex/sweeps", tierPermission, auth.CanRunVariants},
		{http.MethodGet, "/api/vex/sweeps/active", tierPermission, auth.CanViewVariantRun},
		{http.MethodGet, "/api/vex/sweeps/{id}", tierPermission, auth.CanViewVariantRun},
		{http.MethodGet, "/api/vex/sweeps", tierPermission, auth.CanViewVariantRun},
		{http.MethodPost, "/api/vex/sweeps/{id}/cancel", tierPermission, auth.CanCancelScenarioRun},
```

(Match the exact line's surrounding indentation/format by looking at the neighboring entries before inserting — the file uses tab-indented struct literals inside the `routeMatrix` slice.)

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run 'TestCreateVexSweep|TestGetActiveVexSweep|TestCancelVexSweep|TestRBACMatrix' -v`
Expected: build/vet clean; all new tests PASS; `TestRBACMatrix_NoDrift` still PASSES (confirms the 5 new routes are correctly reflected in the matrix).

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/vexsweep_handlers.go orchestrator/internal/api/handlers.go orchestrator/internal/api/variant_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/vexsweep_handlers_test.go
git commit -m "feat(api): add Full Variant Sweep endpoints + same-agent conflict guard on RunVariants"
git push
```

---

### Task 5: `TestRunVariants_RejectsWhenAgentHasRunningSweep`

**Files:**
- Test: `orchestrator/internal/api/variant_handlers_test.go` (append)

**Interfaces:**
- Consumes: the guard added in Task 4 Step 6; `vexsweep.NewStore`/`vexsweep.Sweep` (Task 1).

This is its own task (not folded into Task 4) because it specifically proves the *existing* `RunVariants` handler's new behavior end-to-end, which deserves its own reviewable, independently-runnable test rather than being buried inside Task 4's sweep-creation-focused test file.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/variant_handlers_test.go`:

```go
func TestRunVariants_RejectsWhenAgentHasRunningSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := vexsweep.NewStore(pool)
		if _, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-blocks-adhoc", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		}); err != nil {
			t.Fatalf("Create sweep: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store)
		userID := seedUser(t, pool, "adhoc-blocked-user", "password123", "admin", true)
		body, _ := json.Marshal(map[string]string{"agentId": "agent-blocks-adhoc", "techniqueId": "T1059.003"})
		req := authedRequest(t, http.MethodPost, "/api/variants/run", bytes.NewReader(body), auth.RoleAdmin, userID)
		rec := callAuthed(h.RunVariants, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body: %s", rec.Code, rec.Body.String())
		}
	})
}
```

Add `"bytes"` and `"net/http"` to the file's imports if not already present from Task 3's additions.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRunVariants_RejectsWhenAgentHasRunningSweep -v`
Expected: FAIL — the guard doesn't exist yet in this task's isolated commit history... actually the guard was added in Task 4 Step 6, so if Task 4 is already committed, this test should PASS immediately. If so, skip straight to Step 3 (there's no red state to observe since the implementation predates this test by one task) — this is expected and fine; note it and move on rather than forcing an artificial failure.

- [ ] **Step 3: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestRunVariants_RejectsWhenAgentHasRunningSweep -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/variant_handlers_test.go
git commit -m "test(api): cover RunVariants' same-agent sweep-conflict guard end-to-end"
git push
```

---

### Task 6: `main.go` wiring — start the dispatcher

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `vexsweep.NewStore`, `vexsweep.NewDispatcher`, `(*Dispatcher).SetDispatch`, `(*Dispatcher).Tick` (Tasks 1-2); `Handler.dispatchVariantForSweep`, `Handler.WithVexSweep` (Task 3); `exercise.NewPollScheduler` (existing).
- Produces: nothing new for other code — this is the production wiring, verified by `go build` + the handler tests already covering `Create`/`Cancel` behavior through the real `Handler`. `main.go` has no dedicated test harness anywhere in this codebase (confirmed — every other scheduler/`.With*` wiring in this file is verified the same way), so this task has no new automated test, matching existing convention rather than inventing one.

- [ ] **Step 1: Add the store, dispatcher construction, and scheduler start**

In `orchestrator/cmd/server/main.go`, add `"github.com/audspect/bas/internal/vexsweep"` to the import block. Immediately before the line `hub := ws.NewHub()` (line 369), add:

```go
	// Full Variant Sweep — server-owned orchestration (survives reloads/
	// browser crashes). Ticks every 5s, matching the Exercise engine's own
	// cadence, since variant runs take real wall-clock time (agent
	// execution + result submission) -- no need for tighter polling.
	vexSweepStore := vexsweep.NewStore(pool)
	vexSweepScheduler := exercise.NewPollScheduler(5 * time.Second)
	vexSweepDispatcher := vexsweep.NewDispatcher(vexSweepStore, func(ctx context.Context, variantRunID string) (string, error) {
		var status string
		err := pool.QueryRow(ctx, `SELECT status FROM variant_runs WHERE id = $1`, variantRunID).Scan(&status)
		return status, err
	})
```

- [ ] **Step 2: Add `.WithVexSweep(...)` to the handler chain**

Immediately after the existing `.WithRuleLibrary(rulesEngine).` line (line 386) in the `handler := api.New(...)` chain, add:

```go
		WithVexSweep(vexSweepStore).
```

(Keep it before the final `.WithIOCProvider(iocProvider)` line, which has no trailing `.` — match the existing chain's formatting exactly.)

- [ ] **Step 3: Wire the dispatch callback and start the scheduler**

Immediately after the `handler := api.New(...)....WithIOCProvider(iocProvider)` chain assignment completes (right after line 387), add:

```go
	vexSweepDispatcher.SetDispatch(handler.dispatchVariantForSweep)
	vexSweepScheduler.Start(func(ctx context.Context) {
		if err := vexSweepDispatcher.Tick(ctx); err != nil {
			log.Printf("[vexsweep] tick: %v", err)
		}
	})
	defer vexSweepScheduler.Stop()
```

- [ ] **Step 4: Verify the build**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: clean, no output.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/cmd/server/main.go
git commit -m "feat(main): start the Full Variant Sweep dispatcher (5s tick, survives reloads)"
git push
```

---

### Task 7: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1 > /tmp/vexsweep-full-suite.log 2>&1; echo "EXIT_CODE:$?"`

Expected: `EXIT_CODE:0`, every package `ok`. If a single package fails under Docker load with a testcontainers connection error, re-run that package in isolation before concluding it's the known transient flake (this session's established distinction: one package failing under full-suite load is usually transient; many/all packages failing identically means check `docker info` first — it's a genuine outage, not a flake).

- [ ] **Step 2: Report completion**

This sub-project executes directly on `main` (matching this session's established inline-execution convention) — no branch/worktree/PR decision needed. Confirm with the user that Sub-project A is complete, and that Sub-project B (frontend: resume-on-reload UI, variant-based smooth progress bar, nested progress display) is next, unstarted.
