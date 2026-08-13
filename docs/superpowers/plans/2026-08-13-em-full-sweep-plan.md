# Endpoint Mastery Full Sweep — Server-Side Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix Endpoint Mastery's "Run Full Sweep" button, which today has no agent/group picker (hardcodes `agents[0]`) and only ever successfully runs the first of its 14 layers (the client-side dispatch loop advances on "dispatched," not "completed," hitting the one-scenario-per-agent concurrency guard on every subsequent layer).

**Architecture:** A new `internal/emsweep` package — `Store` (Postgres CRUD over a new `em_sweeps` table) + `Dispatcher` (a 5-second-tick poller that dispatches one layer at a time, waits for it to reach a terminal status, then dispatches the next) — mirrors `internal/vexsweep`'s existing, working pattern almost exactly, simplified because an EM layer is one plain scenario dispatch, not an ART technique fanned into variants. A new `internal/api/emsweep_handlers.go` exposes 6 HTTP endpoints under `/api/em/sweeps*`. The frontend gets a new EM-specific target-picker modal (Individual/Group(s)/All Agents, modeled on but not sharing code with Full Variant Sweep's) and a small live-progress drawer.

**Tech Stack:** Go (orchestrator backend), vanilla JS in `wwwroot/index.html` (frontend), PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-08-13-em-full-sweep-design.md`

## Global Constraints

- Posture mode only — no Telemetry/Lab mode selector for EM sweeps (spec Non-Goals).
- No changes to `internal/vexsweep`, `vex_sweeps`, or any Full Variant Sweep frontend code — `internal/emsweep` is an independent, parallel package (spec Non-Goals).
- No WebSocket push for progress — the frontend polls `GET /api/em/sweeps/{id}` (spec Non-Goals).
- Dispatch failure on a layer marks the whole sweep `failed` — never silently skip to the next layer (spec Architecture §2, matches vexsweep's existing choice).
- Every Go component gets a TDD cycle: write the failing test, run it, confirm the failure, implement, run again, confirm the pass.
- Before every commit that touches `internal/api`, run the **full** `go test ./internal/api/...` suite (not just the new tests) in the background (it takes 8-15 minutes) and read the actual completed log file — never trust a `| tail -N` piped capture, and never assume a background run finished without checking its real output file first (this exact session hit both failure modes).
- Commit after each task (or small logical group of tasks) with a message explaining what changed and why — not one giant commit at the end. `git push` after every commit.
- JS changes get verified with `node --check` on the extracted `<script>` contents (see Task 9 for the exact extraction command) before committing.

---

### Task 1: Database migration — `em_sweeps` table + `scenario_runs.em_sweep_id`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (add a new migration entry near the existing `vex_sweeps` migration, ~line 628-656, and a new `ALTER TABLE scenario_runs` line near the existing `sweep_id` one, ~line 1397-1398)
- Test: `orchestrator/internal/db/postgres_test.go` (if this file doesn't exist, create it following the pattern of any other `internal/db/*_test.go` file in this package — check for one first with `Glob "orchestrator/internal/db/*_test.go"`)

**Interfaces:**
- Produces: the `em_sweeps` table with columns `id, agent_id, layers, current_index, current_scenario_run_id, current_layer_started_at, completed_layers, total_layers, status, error, created_by, started_at, completed_at`, a partial unique index enforcing one running sweep per agent, and `scenario_runs.em_sweep_id` (nullable FK) — every later task depends on this schema existing.

- [ ] **Step 1: Locate the exact insertion point**

Run: `grep -n "vex_sweeps\|idx_scenario_runs_sweep_id" orchestrator/internal/db/postgres.go`

Confirm the `vex_sweeps` table migration block (starts with the comment `// vex_sweeps: server-owned Full Variant Sweep orchestration state.`) and the `scenario_runs.sweep_id` `ALTER TABLE` line. You'll add new entries immediately after each, in the same migration list (this file's migrations are a Go slice of SQL strings run in order at startup — every migration is `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`, so it's safe to re-run and append-only).

- [ ] **Step 2: Add the `em_sweeps` table migration**

Insert immediately after the `vex_sweeps` block's closing `)`,` line (right before the next distinct migration entry):

```go
		// em_sweeps: server-owned Endpoint Mastery Full Sweep orchestration
		// state. One row per sweep; the partial unique index makes "one
		// running sweep per agent" race-safe (not an app-level
		// check-then-insert). See
		// docs/superpowers/specs/2026-08-13-em-full-sweep-design.md.
		`CREATE TABLE IF NOT EXISTS em_sweeps (
			id                        text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id                  text        NOT NULL,
			layers                    text[]      NOT NULL,
			current_index             int         NOT NULL DEFAULT 0,
			current_scenario_run_id   text        NOT NULL DEFAULT '',
			current_layer_started_at  timestamptz,
			completed_layers          int         NOT NULL DEFAULT 0,
			total_layers              int         NOT NULL DEFAULT 0,
			status                    text        NOT NULL DEFAULT 'running',
			error                     text        NOT NULL DEFAULT '',
			created_by                text        NOT NULL DEFAULT '',
			started_at                timestamptz NOT NULL DEFAULT NOW(),
			completed_at              timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_em_sweeps_agent ON em_sweeps (agent_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_em_sweeps_one_running_per_agent
			ON em_sweeps (agent_id) WHERE status = 'running'`,
```

- [ ] **Step 3: Add the `scenario_runs.em_sweep_id` column migration**

Insert immediately after the existing `scenario_runs.sweep_id` `ALTER TABLE`/index pair:

```go
		// Live Runs: collapse Endpoint Mastery Full Sweep layer runs into one
		// row, same pattern as sweep_id for Full Variant Sweep. See
		// docs/superpowers/specs/2026-08-13-em-full-sweep-design.md.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS em_sweep_id text REFERENCES em_sweeps(id)`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_em_sweep_id ON scenario_runs (em_sweep_id)`,
```

This must come **after** the `em_sweeps` table migration in the slice (the `REFERENCES em_sweeps(id)` foreign key requires the table to already exist when this line runs).

- [ ] **Step 4: Verify the migration runs cleanly**

Run: `cd orchestrator && go build ./... 2>&1`

Expected: no output (clean build). This doesn't execute the migration (that needs a real Postgres connection, exercised by the container-backed tests in later tasks), just confirms the Go syntax is valid.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/db/postgres.go
git commit -m "$(cat <<'EOF'
feat(db): add em_sweeps table + scenario_runs.em_sweep_id migration

First piece of Endpoint Mastery Full Sweep's server-side orchestration
(mirrors vex_sweeps' schema and race-safe one-running-sweep-per-agent
partial unique index). See docs/superpowers/specs/2026-08-13-em-full-sweep-design.md.
EOF
)"
git push
```

---

### Task 2: `internal/emsweep` package — `Sweep` type

**Files:**
- Create: `orchestrator/internal/emsweep/sweep.go`

**Interfaces:**
- Consumes: nothing (this is the foundational type).
- Produces: the `Sweep` struct every other task in this package and `internal/api` references by these exact field names.

- [ ] **Step 1: Write the type**

```go
// Package emsweep owns server-side orchestration of the Endpoint Mastery
// Full Sweep feature -- dispatching all 14 EM layers for an agent
// sequentially, tracking progress, and surviving browser reloads/crashes.
// Mirrors internal/vexsweep's pattern, simplified: an EM layer is one plain
// scenario dispatch, not an ART technique fanned into variants, so there is
// no per-layer "variant count" to track -- each layer is worth exactly 1.
// See docs/superpowers/specs/2026-08-13-em-full-sweep-design.md.
package emsweep

import "time"

// Sweep is one Endpoint Mastery Full Sweep's persisted state.
type Sweep struct {
	ID                   string
	AgentID              string
	Layers               []string
	CurrentIndex         int
	CurrentScenarioRunID string
	// CurrentLayerStartedAt is when the current layer was dispatched (nil
	// when no layer is in flight). Dispatcher uses it to detect a layer
	// that has genuinely hung and force-cancel it -- see dispatcher.go's
	// stuckThreshold.
	CurrentLayerStartedAt *time.Time
	CompletedLayers       int
	TotalLayers           int
	Status                string
	Error                 string
	CreatedBy             string
	StartedAt             time.Time
	CompletedAt           *time.Time
}
```

- [ ] **Step 2: Verify it builds**

Run: `cd orchestrator && go build ./internal/emsweep/... 2>&1`

Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/emsweep/sweep.go
git commit -m "feat(emsweep): add Sweep type"
git push
```

---

### Task 3: `internal/emsweep` package — `Store`

**Files:**
- Create: `orchestrator/internal/emsweep/store.go`
- Test: `orchestrator/internal/emsweep/store_test.go`

**Interfaces:**
- Consumes: `Sweep` (Task 2), the `em_sweeps` table (Task 1).
- Produces:
  - `NewStore(pool *pgxpool.Pool) *Store`
  - `(s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error)` — returns `ErrAgentAlreadySweeping` on the partial-unique-index conflict
  - `(s *Store) Get(ctx context.Context, id string) (Sweep, error)`
  - `(s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error)`
  - `(s *Store) ListRunning(ctx context.Context) ([]Sweep, error)`
  - `(s *Store) ListByStatus(ctx context.Context, status string) ([]Sweep, error)`
  - `(s *Store) AdvanceToNext(ctx context.Context, id string, nextIndex int, nextScenarioRunID string) error`
  - `(s *Store) MarkStopped(ctx context.Context, id string) error`
  - `(s *Store) MarkFailed(ctx context.Context, id, errMsg string) error`
  - `ErrAgentAlreadySweeping` (package-level error var)

This is the store every later task (Dispatcher, HTTP handlers) depends on.

- [ ] **Step 1: Check the test-container conventions this repo uses**

Run: `grep -n "sharedDB\|RunWithPool" orchestrator/internal/vexsweep/store_test.go | head -5`

This confirms the exact `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` + `testing.Short()` skip-guard pattern to copy. Read `orchestrator/internal/vexsweep/store_test.go` in full for the exact test shapes (`TestCreate_PersistsAndGetRoundTrips`, `TestCreate_RejectsSecondRunningSweepSameAgent`, `TestCreate_AllowsConcurrentSweepsDifferentAgents`, `TestGetActiveForAgent_FoundAndNotFound`, `TestAdvanceToNext_CreditsAndAdvancesThenCompletes`, `TestMarkStopped_And_MarkFailed`) — you will write the same six tests here, adapted to `emsweep.Sweep`'s simpler shape (no `TechniqueVariantCounts`/`CompletedVariants` fractional crediting — `AdvanceToNext` always credits exactly 1 layer).

- [ ] **Step 2: Write the failing tests**

Create `orchestrator/internal/emsweep/store_test.go`:

```go
package emsweep

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB = testutil.NewSharedTestDB()

func TestCreate_PersistsAndGetRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		created, err := s.Create(context.Background(), Sweep{
			AgentID: "agent-1", Layers: []string{"em-01", "em-02", "em-03"}, TotalLayers: 3, CreatedBy: "tester",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.ID == "" {
			t.Fatal("expected a generated ID")
		}
		if created.Status != "running" {
			t.Fatalf("Status = %q, want running", created.Status)
		}
		got, err := s.Get(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.AgentID != "agent-1" || len(got.Layers) != 3 || got.TotalLayers != 3 {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
	})
}

func TestCreate_RejectsSecondRunningSweepSameAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		if _, err := s.Create(context.Background(), Sweep{AgentID: "agent-2", Layers: []string{"em-01"}, TotalLayers: 1}); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		_, err := s.Create(context.Background(), Sweep{AgentID: "agent-2", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != ErrAgentAlreadySweeping {
			t.Fatalf("second Create err = %v, want ErrAgentAlreadySweeping", err)
		}
	})
}

func TestCreate_AllowsConcurrentSweepsDifferentAgents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		if _, err := s.Create(context.Background(), Sweep{AgentID: "agent-3a", Layers: []string{"em-01"}, TotalLayers: 1}); err != nil {
			t.Fatalf("agent-3a Create: %v", err)
		}
		if _, err := s.Create(context.Background(), Sweep{AgentID: "agent-3b", Layers: []string{"em-01"}, TotalLayers: 1}); err != nil {
			t.Fatalf("agent-3b Create: %v", err)
		}
	})
}

func TestGetActiveForAgent_FoundAndNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		_, found, err := s.GetActiveForAgent(context.Background(), "agent-4-never-swept")
		if err != nil {
			t.Fatalf("GetActiveForAgent (not found): %v", err)
		}
		if found {
			t.Fatal("expected found=false for an agent with no sweep")
		}
		created, err := s.Create(context.Background(), Sweep{AgentID: "agent-4", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, found, err := s.GetActiveForAgent(context.Background(), "agent-4")
		if err != nil {
			t.Fatalf("GetActiveForAgent (found): %v", err)
		}
		if !found || got.ID != created.ID {
			t.Fatalf("GetActiveForAgent = (%+v, %v), want the created sweep", got, found)
		}
	})
}

func TestAdvanceToNext_CreditsAndAdvancesThenCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		sw, err := s.Create(context.Background(), Sweep{AgentID: "agent-5", Layers: []string{"em-01", "em-02"}, TotalLayers: 2})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// Advance to layer 1 (index 1), crediting layer 0 as complete.
		if err := s.AdvanceToNext(context.Background(), sw.ID, 1, "run-em-02"); err != nil {
			t.Fatalf("AdvanceToNext (to layer 1): %v", err)
		}
		got, err := s.Get(context.Background(), sw.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.CurrentIndex != 1 || got.CurrentScenarioRunID != "run-em-02" || got.Status != "running" {
			t.Fatalf("after first advance: %+v", got)
		}
		// Advance past the last layer -- nextScenarioRunID == "" means "no more layers".
		if err := s.AdvanceToNext(context.Background(), sw.ID, 2, ""); err != nil {
			t.Fatalf("AdvanceToNext (complete): %v", err)
		}
		got, err = s.Get(context.Background(), sw.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != "completed" || got.CurrentScenarioRunID != "" || got.CompletedAt == nil {
			t.Fatalf("after completing advance: %+v", got)
		}
	})
}

func TestMarkStopped_And_MarkFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		sw1, _ := s.Create(context.Background(), Sweep{AgentID: "agent-6a", Layers: []string{"em-01"}, TotalLayers: 1})
		if err := s.MarkStopped(context.Background(), sw1.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}
		got1, _ := s.Get(context.Background(), sw1.ID)
		if got1.Status != "stopped" {
			t.Fatalf("Status = %q, want stopped", got1.Status)
		}

		sw2, _ := s.Create(context.Background(), Sweep{AgentID: "agent-6b", Layers: []string{"em-01"}, TotalLayers: 1})
		if err := s.MarkFailed(context.Background(), sw2.ID, "layer dispatch exploded"); err != nil {
			t.Fatalf("MarkFailed: %v", err)
		}
		got2, _ := s.Get(context.Background(), sw2.ID)
		if got2.Status != "failed" || got2.Error != "layer dispatch exploded" {
			t.Fatalf("after MarkFailed: %+v", got2)
		}
	})
}
```

Check the exact import path/name for the shared test-DB helper this repo uses first: run `grep -rn "sharedDB\s*=" orchestrator/internal/vexsweep/*_test.go` and use whatever it actually resolves to (the `testutil.NewSharedTestDB()` call above is illustrative — copy the *exact* line vexsweep's test file uses, package path included, since this project may alias it differently).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/emsweep/... -v 2>&1`

Expected: compile failure (`Store`, `NewStore`, `ErrAgentAlreadySweeping` undefined) — this proves the tests are wired to real (not-yet-existing) symbols, not vacuously passing.

- [ ] **Step 3: Write the minimal implementation**

Create `orchestrator/internal/emsweep/store.go`:

```go
package emsweep

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAgentAlreadySweeping is returned by Create when the partial unique
// index rejects a second running sweep for the same agent.
var ErrAgentAlreadySweeping = errors.New("agent already has a running EM sweep")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const sweepCols = `id, agent_id, layers, current_index, current_scenario_run_id,
	current_layer_started_at, completed_layers, total_layers, status, error,
	created_by, started_at, completed_at`

func scanSweep(row interface {
	Scan(dest ...any) error
}) (Sweep, error) {
	var sw Sweep
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Layers, &sw.CurrentIndex, &sw.CurrentScenarioRunID,
		&sw.CurrentLayerStartedAt, &sw.CompletedLayers, &sw.TotalLayers, &sw.Status, &sw.Error,
		&sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt)
	return sw, err
}

func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO em_sweeps (agent_id, layers, total_layers, created_by)
		 VALUES ($1,$2,$3,$4)
		 RETURNING `+sweepCols,
		sw.AgentID, sw.Layers, sw.TotalLayers, sw.CreatedBy)
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
	row := s.pool.QueryRow(ctx, `SELECT `+sweepCols+` FROM em_sweeps WHERE id = $1`, id)
	return scanSweep(row)
}

func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+sweepCols+` FROM em_sweeps WHERE agent_id = $1 AND status = 'running'`, agentID)
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
	rows, err := s.pool.Query(ctx, `SELECT `+sweepCols+` FROM em_sweeps WHERE status = $1 ORDER BY started_at`, status)
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

// AdvanceToNext sets current_index to nextIndex (the caller-computed next
// index -- unchanged for a sweep's very first dispatch, current+1 only when
// advancing past an already-dispatched layer) and records the new
// current_scenario_run_id. nextScenarioRunID == "" means "no next layer" --
// the sweep is marked completed instead. Every call credits exactly one
// layer to completed_layers (unlike vexsweep's variable variant-count
// credit): an EM layer is always worth 1.
func (s *Store) AdvanceToNext(ctx context.Context, id string, nextIndex int, nextScenarioRunID string) error {
	if nextScenarioRunID == "" {
		_, err := s.pool.Exec(ctx,
			`UPDATE em_sweeps
			    SET completed_layers = completed_layers + 1,
			        current_index = $2,
			        current_scenario_run_id = '', current_layer_started_at = NULL,
			        status = 'completed', completed_at = NOW()
			  WHERE id = $1`,
			id, nextIndex)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps
		    SET completed_layers = completed_layers + 1,
		        current_index = $2,
		        current_scenario_run_id = $3, current_layer_started_at = NOW()
		  WHERE id = $1`,
		id, nextIndex, nextScenarioRunID)
	return err
}

func (s *Store) MarkStopped(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps SET status = 'stopped', completed_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps SET status = 'failed', error = $2, completed_at = NOW() WHERE id = $1`, id, errMsg)
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

**IMPORTANT correctness note for the very first call to `AdvanceToNext`:** when a sweep is first created, `completed_layers` should stay `0` until layer 0 *finishes*, not when it's first dispatched. Re-examine this against vexsweep's actual `AdvanceToNext` semantics (`internal/vexsweep/store.go`) before finalizing: vexsweep's version takes an explicit `justCompletedVariants int` parameter so the *caller* (the Dispatcher) controls whether this call credits 0 (dispatching the very first technique, nothing has finished yet) or a real count (advancing past a finished technique). The simplified signature above always credits 1, which is **wrong for the first dispatch** (nothing has completed yet when layer 0 is first sent). Fix this before Step 4: add a `justCompleted int` parameter mirroring vexsweep exactly:

```go
func (s *Store) AdvanceToNext(ctx context.Context, id string, justCompleted, nextIndex int, nextScenarioRunID string) error {
	if nextScenarioRunID == "" {
		_, err := s.pool.Exec(ctx,
			`UPDATE em_sweeps
			    SET completed_layers = completed_layers + $2,
			        current_index = $3,
			        current_scenario_run_id = '', current_layer_started_at = NULL,
			        status = 'completed', completed_at = NOW()
			  WHERE id = $1`,
			id, justCompleted, nextIndex)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps
		    SET completed_layers = completed_layers + $2,
		        current_index = $3,
		        current_scenario_run_id = $4, current_layer_started_at = NOW()
		  WHERE id = $1`,
		id, justCompleted, nextIndex, nextScenarioRunID)
	return err
}
```

Use **this** corrected signature (with `justCompleted`) in the actual file, and update the Step 1 test's two `AdvanceToNext` calls accordingly: the first real call in `TestAdvanceToNext_CreditsAndAdvancesThenCompletes` should be `s.AdvanceToNext(context.Background(), sw.ID, 1, 1, "run-em-02")` (crediting 1 for the just-finished layer 0, advancing to index 1), and the completing call should be `s.AdvanceToNext(context.Background(), sw.ID, 1, 2, "")` (crediting the just-finished layer 1). Go back and fix the test code in Step 1 to match before running Step 2.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/emsweep/... -v 2>&1`

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/emsweep/store.go internal/emsweep/store_test.go
git commit -m "feat(emsweep): add Store (Postgres CRUD for em_sweeps)"
git push
```

---

### Task 4: `internal/emsweep` package — `Dispatcher`

**Files:**
- Create: `orchestrator/internal/emsweep/dispatcher.go`
- Test: `orchestrator/internal/emsweep/dispatcher_test.go`

**Interfaces:**
- Consumes: `Store` (Task 3).
- Produces:
  - `type DispatchFn func(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error)`
  - `type StatusFn func(ctx context.Context, scenarioRunID string) (status string, err error)`
  - `type CancelFn func(ctx context.Context, scenarioRunID string) (agentID, status string, err error)`
  - `NewDispatcher(store *Store, status StatusFn) *Dispatcher`
  - `(d *Dispatcher) SetDispatch(fn DispatchFn)`
  - `(d *Dispatcher) SetCancel(fn CancelFn)`
  - `(d *Dispatcher) Tick(ctx context.Context) error`

This is the component `internal/api`'s `WithEMSweep` (Task 5) and `cmd/server/main.go` (Task 7) both wire into.

**Before writing anything**, read `orchestrator/internal/vexsweep/dispatcher.go` and `orchestrator/internal/vexsweep/dispatcher_test.go` in full. The dispatcher.go you read is this session's *already-fixed* version — it has two bug fixes baked in that must be copied exactly, not the naive version:

1. `advance()` calls `maybeForceCancelStuck` on **both** the `status == "running"` branch **and** the `status-check-errored` branch (a persistent status-check failure must not permanently block stuck-recovery).
2. `maybeForceCancelStuck` sets its `cancelTriggeredForRun` dedup flag **only after** a successful cancel call, never before (a failed cancel attempt must retry on the next tick, not be abandoned forever).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/emsweep/dispatcher_test.go`, following `internal/vexsweep/dispatcher_test.go`'s exact structure and conventions (`sharedDB.RunWithPool`, `testing.Short()` skip guard, `store.Create` + `store.AdvanceToNext` for seeding, `d.stuckThreshold = time.Millisecond` + `time.Sleep(5 * time.Millisecond)` to simulate elapsed time without a real 3-minute wait, `d.SetDispatch`/`d.SetCancel` fakes that record calls in a slice/map). Write these tests, adapted to EM's simpler (no-variant) shape:

- `TestDispatcher_Tick_DispatchesFirstLayerForNewSweep` — a freshly created sweep (via `store.Create`) with `CurrentScenarioRunID == ""` gets `dispatchNextLayer` called with layer index 0 on the first `Tick`.
- `TestDispatcher_Tick_AdvancesWhenCurrentLayerFinishes` — a sweep whose `CurrentScenarioRunID`'s status (per the fake `StatusFn`) is `"completed"` advances to the next layer on the next `Tick`.
- `TestDispatcher_Tick_CompletesSweepAfterLastLayer` — a sweep on its last layer, once that layer's status is terminal, transitions to `status = "completed"`.
- `TestDispatcher_Tick_MarksFailedOnDispatchError` — if the fake `DispatchFn` returns an error, the sweep's status becomes `"failed"` with that error message, and no further layers are attempted.
- `TestDispatcher_Tick_ForceCancelsStuckLayerAfterThreshold` — a layer whose status stays `"running"` past `stuckThreshold` triggers a `CancelFn` call.
- `TestDispatcher_Tick_DoesNotForceCancelBeforeThreshold` — same setup, but before the threshold elapses, no cancel call happens.
- `TestDispatcher_Tick_DoesNotReTriggerCancelOnSubsequentTicks` — after one successful cancel trigger, further ticks (while still stuck) do not call `CancelFn` again.
- `TestDispatcher_Tick_RetriesStuckCancelAfterFailedAttempt` — if the fake `CancelFn` returns an error on the first attempt, the next tick retries it (this is the exact regression this session's vexsweep fix addressed — port the identical test here rather than rediscovering the bug later).
- `TestDispatcher_Tick_ForceCancelsStuckLayerEvenIfStatusCheckErrors` — if the fake `StatusFn` returns an error every time (not just once), stuck-recovery still fires (the other half of this session's vexsweep fix).
- `TestDispatcher_Tick_IgnoresStoppedAndFailedSweeps` — sweeps with `status` other than `"running"` are never touched by `Tick`.

Write the actual Go test code for each of these now, copying `internal/vexsweep/dispatcher_test.go`'s exact style line-for-line but substituting `emsweep.Sweep`'s field names (`Layers` not `Techniques`, `CurrentScenarioRunID` used directly as the "current run" — no separate `CurrentVariantRunID`, `CurrentLayerStartedAt` not `CurrentTechniqueStartedAt`) and the simpler `DispatchFn`/`StatusFn` signatures above (no `mode`/`includeAdvanced`/`totalVariants` parameters — an EM layer dispatch only needs `sweepID, agentID, scenarioID`). Do not skip any of the 10 tests listed — each one locks in a real behavior this dispatcher must have from day one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/emsweep/... -run "TestDispatcher" -v 2>&1`

Expected: compile failure (`Dispatcher`, `NewDispatcher`, `DispatchFn`, `StatusFn`, `CancelFn` undefined).

- [ ] **Step 3: Write the minimal implementation**

Create `orchestrator/internal/emsweep/dispatcher.go`:

```go
package emsweep

import (
	"context"
	"log"
	"time"
)

// DispatchFn dispatches one EM layer (a plain scenario) to an agent.
// Injected after construction (SetDispatch) to avoid an
// internal/emsweep -> internal/api import cycle -- the same pattern
// internal/vexsweep.DispatchFn and internal/exercise.Executor already use.
type DispatchFn func(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error)

// StatusFn reports a scenario_run's current status ("running"/"completed"/
// "failed"/"partial"), read directly from scenario_runs -- no callback into
// internal/api needed, since it's a plain read of a table emsweep can query
// itself. Mirrors vexsweep.VariantRunStatusFn.
type StatusFn func(ctx context.Context, scenarioRunID string) (status string, err error)

// CancelFn cancels an in-flight scenario_run -- injected after construction
// (SetCancel), same import-cycle-avoidance pattern as DispatchFn.
// Production wiring points this at the exact same Handler.cancelScenarioRun
// vexsweep's CancelFn uses -- no new cancellation logic, just reused.
type CancelFn func(ctx context.Context, scenarioRunID string) (agentID, status string, err error)

// defaultStuckThreshold mirrors vexsweep's: how long a layer can sit with
// no progress before the Dispatcher treats it as genuinely hung and
// force-cancels it. See internal/vexsweep/dispatcher.go's identical
// constant for the full rationale (a real ART/Custom check can hang
// unattended the same way an ART atomic can).
const defaultStuckThreshold = 3 * time.Minute

type Dispatcher struct {
	store    *Store
	status   StatusFn
	dispatch DispatchFn
	cancel   CancelFn

	stuckThreshold time.Duration
	// cancelTriggeredForRun tracks scenario_run_ids a stuck-cancel has
	// already been triggered for, so advance() doesn't re-trigger it every
	// 5s tick while the cancel's own grace period is still resolving.
	cancelTriggeredForRun map[string]bool
}

func NewDispatcher(store *Store, status StatusFn) *Dispatcher {
	return &Dispatcher{
		store: store, status: status,
		stuckThreshold:        defaultStuckThreshold,
		cancelTriggeredForRun: make(map[string]bool),
	}
}

func (d *Dispatcher) SetDispatch(fn DispatchFn) { d.dispatch = fn }
func (d *Dispatcher) SetCancel(fn CancelFn)     { d.cancel = fn }

// Tick advances every running sweep by at most one step. Exported so tests
// can call it directly without a real ticker; production wiring calls it
// from an exercise.PollScheduler tick callback.
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
	if sw.CurrentScenarioRunID != "" {
		status, err := d.status(ctx, sw.CurrentScenarioRunID)
		if err != nil {
			log.Printf("[emsweep] status check failed for sweep %s run %s: %v", sw.ID, sw.CurrentScenarioRunID, err)
			// A persistent status-check failure must not permanently block
			// stuck-recovery -- see internal/vexsweep/dispatcher.go's
			// identical fix.
			d.maybeForceCancelStuck(ctx, sw)
			return
		}
		if status == "running" {
			d.maybeForceCancelStuck(ctx, sw)
			return // nothing to do this tick
		}
		delete(d.cancelTriggeredForRun, sw.CurrentScenarioRunID)
		// Layer finished (completed/failed/partial) -- credit it and advance.
		d.dispatchNext(ctx, sw, 1)
		return
	}
	// No layer in flight yet -- this is the sweep's very first tick.
	d.dispatchNext(ctx, sw, 0)
}

// maybeForceCancelStuck triggers a cancel for the current layer once it has
// exceeded stuckThreshold with no progress. Triggers at most once per
// scenario_run. Sets the dedup flag ONLY after a successful cancel call --
// see internal/vexsweep/dispatcher.go's identical fix: a failed cancel
// attempt (e.g. transient WS-send error) must retry on the next tick, not
// be abandoned forever.
func (d *Dispatcher) maybeForceCancelStuck(ctx context.Context, sw Sweep) {
	if d.cancel == nil || sw.CurrentScenarioRunID == "" || sw.CurrentLayerStartedAt == nil {
		return
	}
	if time.Since(*sw.CurrentLayerStartedAt) <= d.stuckThreshold {
		return
	}
	if d.cancelTriggeredForRun[sw.CurrentScenarioRunID] {
		return
	}

	layer := ""
	if sw.CurrentIndex >= 0 && sw.CurrentIndex < len(sw.Layers) {
		layer = sw.Layers[sw.CurrentIndex]
	}
	if _, _, err := d.cancel(ctx, sw.CurrentScenarioRunID); err != nil {
		log.Printf("[emsweep] force-cancel stuck layer %s for sweep %s (run %s): %v -- will retry next tick", layer, sw.ID, sw.CurrentScenarioRunID, err)
		return
	}
	d.cancelTriggeredForRun[sw.CurrentScenarioRunID] = true
	log.Printf("[emsweep] layer %s for sweep %s exceeded stuck threshold (%s) -- force-cancel triggered", layer, sw.ID, d.stuckThreshold)
}

func (d *Dispatcher) dispatchNext(ctx context.Context, sw Sweep, justFinishedCount int) {
	nextIdx := sw.CurrentIndex
	if sw.CurrentScenarioRunID != "" {
		nextIdx = sw.CurrentIndex + 1
	}
	if nextIdx >= len(sw.Layers) {
		if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, ""); err != nil {
			log.Printf("[emsweep] complete sweep %s: %v", sw.ID, err)
		}
		return
	}

	scenarioRunID, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Layers[nextIdx])
	if err != nil {
		// Deliberately does not fall through to the next layer -- a
		// silently-skipped layer in a security-validation sweep is worse
		// than a sweep that stops and says why. Matches vexsweep's identical
		// choice.
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[emsweep] mark sweep %s failed: %v", sw.ID, merr)
		}
		return
	}
	if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, scenarioRunID); err != nil {
		log.Printf("[emsweep] advance sweep %s: %v", sw.ID, err)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/emsweep/... -v 2>&1`

Expected: all tests in the package PASS (both `store_test.go` and `dispatcher_test.go`).

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/emsweep/dispatcher.go internal/emsweep/dispatcher_test.go
git commit -m "feat(emsweep): add Dispatcher (sequential layer dispatch + stuck-layer force-cancel)"
git push
```

---

### Task 5: `internal/api` — `dispatchEMLayer` + `WithEMSweep` + Handler field

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (add the `emSweep` field near the existing `vexSweep` field at line ~108; add `WithEMSweep` near `WithVexSweep` at line ~398-406)
- Create: `orchestrator/internal/api/em_dispatch.go` (the `dispatchEMLayer` function — kept in its own small file rather than growing `handlers.go` further, following this codebase's existing pattern of splitting dispatch-glue functions into their own files, e.g. `scheduled_assessment_dispatch.go`, `job_dispatch.go`)
- Test: `orchestrator/internal/api/em_dispatch_test.go`

**Interfaces:**
- Consumes: `dispatchRun` (existing, `handlers.go:1212`), `dispatchOpts` (existing, `handlers.go:1109`), `h.engine.Get` (existing scenario lookup), `emsweep.Store`/`emsweep.Dispatcher` (Tasks 3-4).
- Produces: `h.emSweep *emsweep.Store` field, `(h *Handler) WithEMSweep(store *emsweep.Store, dispatcher *emsweep.Dispatcher) *Handler`, `(h *Handler) dispatchEMLayer(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error)` — Task 7 (main.go wiring) and Task 6 (HTTP handlers) both depend on these.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/em_dispatch_test.go`. Follow `internal/api/variant_handlers_test.go`'s `TestHandler_WithVexSweep_StoresReference`-style test for the `WithEMSweep` half, and a dispatch test modeled on how `scheduled_assessment_dispatch.go`'s dispatch function is tested (check `internal/api/scheduled_assessment_dispatch_test.go` if it exists, else follow `campaign_crud_test.go`'s `minimalPostureScenario`/`seedActiveAgent`/`startFakeAgent` conventions):

```go
package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/emsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHandler_WithEMSweep_StoresReference(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	store := emsweep.NewStore(nil)
	dispatcher := emsweep.NewDispatcher(store, func(ctx context.Context, id string) (string, error) { return "", nil })
	h.WithEMSweep(store, dispatcher)
	if h.emSweep != store {
		t.Fatal("WithEMSweep did not store the emsweep.Store reference on the Handler")
	}
}

func TestDispatchEMLayer_DispatchesAndTagsRunWithSweepID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "em-dispatch-sc")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "em-dispatch-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, err := h.dispatchEMLayer(context.Background(), "sweep-123", agentID, sc.ID)
		if err != nil {
			t.Fatalf("dispatchEMLayer: %v", err)
		}
		if runID == "" {
			t.Fatal("expected a non-empty scenario_run id")
		}

		var mode, emSweepID string
		if err := pool.QueryRow(context.Background(),
			`SELECT em_sweep_id FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&emSweepID); err != nil {
			t.Fatalf("query em_sweep_id: %v", err)
		}
		if emSweepID != "sweep-123" {
			t.Fatalf("em_sweep_id = %q, want %q", emSweepID, "sweep-123")
		}
		_ = mode // silence unused-var if you don't end up needing it
	})
}

func TestDispatchEMLayer_UnknownScenario_ReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-dispatch-other-sc")
		h := New(pool, ws.NewHub(), engine, "")
		_, err := h.dispatchEMLayer(context.Background(), "sweep-1", "some-agent", "does-not-exist")
		if err == nil {
			t.Fatal("expected an error for an unknown scenario id")
		}
	})
}
```

Remove the unused `mode` variable from the first test before running it (it was left in accidentally in this draft — delete the `var mode, emSweepID string` line's `mode,` part and the `_ = mode` line entirely; declare just `var emSweepID string`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestHandler_WithEMSweep|TestDispatchEMLayer" -v 2>&1`

Expected: compile failure (`h.WithEMSweep`, `h.dispatchEMLayer`, `h.emSweep` undefined, `emsweep` package doesn't exist as an import target yet in this file).

- [ ] **Step 3: Add the `emSweep` field and `WithEMSweep` method**

In `orchestrator/internal/api/handlers.go`, find the existing field (run `grep -n "vexSweep\s*\*vexsweep.Store" internal/api/handlers.go` to confirm its current line) and add immediately after it:

```go
	emSweep               *emsweep.Store       // nil when not loaded — Endpoint Mastery Full Sweep orchestration
```

Add `"github.com/audspect/bas/internal/emsweep"` to this file's import block (alongside the existing `"github.com/audspect/bas/internal/vexsweep"` import).

Find `WithVexSweep` (run `grep -n "func (h \*Handler) WithVexSweep" internal/api/handlers.go` to confirm its current line) and add immediately after its closing `}`:

```go
// WithEMSweep attaches the Endpoint Mastery Full Sweep store and wires the
// Dispatcher's DispatchFn to dispatchEMLayer -- same wire-the-callback-
// inside-the-api-package pattern WithVexSweep already uses.
func (h *Handler) WithEMSweep(store *emsweep.Store, dispatcher *emsweep.Dispatcher) *Handler {
	h.emSweep = store
	dispatcher.SetDispatch(h.dispatchEMLayer)
	// Reuses cancelScenarioRun's existing agent-notify + grace-period +
	// variant_runs-sync behavior for the Dispatcher's stuck-layer backstop,
	// rather than duplicating any of that inside emsweep.
	dispatcher.SetCancel(h.cancelScenarioRun)
	return h
}
```

- [ ] **Step 4: Write `dispatchEMLayer`**

Create `orchestrator/internal/api/em_dispatch.go`:

```go
package api

import (
	"context"
	"fmt"
	"log"
)

// dispatchEMLayer is the emsweep.DispatchFn implementation -- looks up the
// layer's scenario and dispatches it via the same dispatchRun core
// RunScenario, campaign fan-out, and scheduled assessments all share. Much
// simpler than vexsweep's dispatchVariantForSweep: an EM layer is one plain
// posture scenario, not an ART technique needing variant-template
// resolution.
func (h *Handler) dispatchEMLayer(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error) {
	sc, ok := h.engine.Get(scenarioID)
	if !ok {
		return "", fmt.Errorf("EM layer scenario %q not found", scenarioID)
	}
	runID, skip, err := h.dispatchRun(ctx, sc, agentID, dispatchOpts{Mode: "posture"})
	if err != nil {
		return "", err
	}
	if skip != "" {
		return "", fmt.Errorf("layer skipped: %s", skip)
	}
	if _, err := h.db.Exec(ctx, `UPDATE scenario_runs SET em_sweep_id = $1 WHERE id = $2`, sweepID, runID); err != nil {
		log.Printf("[emsweep] tag run %s with sweep %s: %v", runID, sweepID, err)
	}
	return runID, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestHandler_WithEMSweep|TestDispatchEMLayer" -v 2>&1`

Expected: all 3 tests PASS.

- [ ] **Step 6: Run the FULL `internal/api` suite before committing**

Run in the background (it takes 8-15 minutes):

```bash
cd orchestrator && go test ./internal/api/... -timeout 20m > /tmp/em-task5-test.log 2>&1
```

Use `run_in_background: true`. Wait for the actual completion notification, then read the **full** log file (not a piped/truncated view) — `tail -n 10 /tmp/em-task5-test.log` — and confirm it ends with `ok  	github.com/audspect/bas/internal/api	<N>s`, not a `FAIL`. Do not proceed to Step 7 on an assumption; read the real file.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/handlers.go internal/api/em_dispatch.go internal/api/em_dispatch_test.go
git commit -m "feat(api): add dispatchEMLayer + WithEMSweep wiring"
git push
```

---

### Task 6: `internal/api` — HTTP handlers + RBAC matrix entries

**Files:**
- Create: `orchestrator/internal/api/emsweep_handlers.go`
- Test: `orchestrator/internal/api/emsweep_handlers_test.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add 6 new route entries)

**Interfaces:**
- Consumes: `h.emSweep` (Task 5), `emsweep.Sweep`/`Store` (Tasks 2-3), `EM_CATALOG`'s 14 scenario IDs (currently only defined client-side in `wwwroot/index.html:17683-17697` — this task needs a server-side equivalent; see Step 3 below for where it lives), `errRunNotRunning` (existing, `handlers.go:2402`), `h.cancelScenarioRun` (existing, `handlers.go:2410`), `scanRunRows`/`runRow` (existing, used by `GetVexSweepRuns` — reuse directly, it's a generic `scenario_runs` row scanner, not vexsweep-specific).
- Produces: `CreateEMSweep`, `GetActiveEMSweep`, `GetEMSweep`, `GetEMSweepRuns`, `ListEMSweeps`, `CancelEMSweep` — Task 8 (frontend) calls all 6.

- [ ] **Step 1: Decide where the server-side EM layer catalog lives**

The frontend's `EM_CATALOG` (14 `{id, num, name, desc}` entries) only exists in JS today. `CreateEMSweep` needs the same 14 scenario IDs server-side to resolve `layers` (per spec Architecture §1: "never trusts a client-submitted list"). Add a small Go equivalent in the new `emsweep_handlers.go` file itself (not a new package-level file, since it's only consumed by `CreateEMSweep`):

```go
// emLayerIDs lists the 14 Endpoint Mastery scenario IDs, in sweep order.
// Mirrors EM_CATALOG in wwwroot/index.html:17683-17697 -- keep both lists
// in sync if EM layers are ever added/removed/reordered.
var emLayerIDs = []string{
	"em-01-control-validation", "em-02-attack-behavioral-depth", "em-03-memory-attacks",
	"em-04-credential-theft", "em-05-persistence-validation", "em-06-defense-evasion",
	"em-07-ransomware-readiness", "em-08-exploit-mitigation", "em-09-browser-attack",
	"em-10-endpoint-exfiltration", "em-11-hardening-validation", "em-12-adversary-emulation",
	"em-13-product-validation", "em-14-continuous-validation",
}
```

- [ ] **Step 2: Write the failing tests**

Create `orchestrator/internal/api/emsweep_handlers_test.go`, following `campaign_crud_test.go`'s `authedRequest`/`callAuthed` + `minimalPostureScenario`/`seedActiveAgent`/`startFakeAgent` conventions (read those helpers' current signatures first: `grep -n "func minimalPostureScenario\|func seedActiveAgent\|func startFakeAgent\|func authedRequest\|func callAuthed" orchestrator/internal/api/*_test.go`):

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateEMSweep_DispatchesFirstLayerEventually(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// Register at least one real em-*-... scenario so the server-side
		// catalog resolution (Step 1's emLayerIDs, filtered against
		// h.engine) has something to find -- mirrors how
		// minimalPostureScenario registers a scenario under a chosen ID.
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		h := New(pool, ws.NewHub(), engine, testJWTSecret)
		agentID := "em-create-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-create-user", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"agentId": agentID})
		req := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateEMSweep, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["agentId"] != agentID {
			t.Fatalf("response agentId = %v, want %v", out["agentId"], agentID)
		}
		layers, _ := out["layers"].([]any)
		if len(layers) != 1 || layers[0] != "em-01-control-validation" {
			t.Fatalf("expected exactly the one registered EM layer, got %v", layers)
		}
	})
}

func TestCreateEMSweep_RejectsSecondSweepSameAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		h := New(pool, ws.NewHub(), engine, testJWTSecret)
		agentID := "em-conflict-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-conflict-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"agentId": agentID})

		req1 := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		if rec := callAuthed(h.CreateEMSweep, req1); rec.Code != http.StatusCreated {
			t.Fatalf("first create: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		req2 := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec2 := callAuthed(h.CreateEMSweep, req2)
		if rec2.Code != http.StatusConflict {
			t.Fatalf("second create: status = %d, want 409, body = %s", rec2.Code, rec2.Body.String())
		}
	})
}

func TestGetActiveEMSweep_404WhenNoneRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		uid := seedUser(t, pool, "em-active-user", "pw-Password1!", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/em/sweeps/active?agentId=em-no-sweep-agent", nil, auth.RoleViewer, uid)
		rec := callAuthed(h.GetActiveEMSweep, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestCancelEMSweep_StopsSweepAndCancelsCurrentRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		h := New(pool, ws.NewHub(), engine, testJWTSecret)
		agentID := "em-cancel-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-cancel-user", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"agentId": agentID})
		createReq := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateEMSweep, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		sweepID, _ := created["id"].(string)
		if sweepID == "" {
			t.Fatalf("no sweep id in create response: %s", createRec.Body.String())
		}

		cancelReq := withURLParam(authedRequest(t, http.MethodPost, "/api/em/sweeps/"+sweepID+"/cancel", nil, auth.RoleAdmin, uid), "id", sweepID)
		cancelRec := callAuthed(h.CancelEMSweep, cancelReq)
		if cancelRec.Code != http.StatusOK {
			t.Fatalf("cancel status = %d, want 200, body = %s", cancelRec.Code, cancelRec.Body.String())
		}

		var status string
		if err := pool.QueryRow(nil, `SELECT status FROM em_sweeps WHERE id = $1`, sweepID).Scan(&status); err == nil && status != "stopped" {
			t.Fatalf("status = %q, want stopped", status)
		}
	})
}
```

Note the last test's `pool.QueryRow(nil, ...)` is invalid (a `nil` context) — replace it with `pool.QueryRow(context.Background(), ...)` and add `"context"` to the imports before running.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateEMSweep|TestGetActiveEMSweep|TestCancelEMSweep" -v 2>&1`

Expected: compile failure (`h.CreateEMSweep` etc. undefined).

- [ ] **Step 4: Write the minimal implementation**

Create `orchestrator/internal/api/emsweep_handlers.go`, directly adapted from `internal/api/vexsweep_handlers.go` (read that file first if you haven't already this task — Task 6 Step 1 assumed you have):

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/emsweep"
)

// emLayerIDs lists the 14 Endpoint Mastery scenario IDs, in sweep order.
// Mirrors EM_CATALOG in wwwroot/index.html:17683-17697 -- keep both lists
// in sync if EM layers are ever added/removed/reordered.
var emLayerIDs = []string{
	"em-01-control-validation", "em-02-attack-behavioral-depth", "em-03-memory-attacks",
	"em-04-credential-theft", "em-05-persistence-validation", "em-06-defense-evasion",
	"em-07-ransomware-readiness", "em-08-exploit-mitigation", "em-09-browser-attack",
	"em-10-endpoint-exfiltration", "em-11-hardening-validation", "em-12-adversary-emulation",
	"em-13-product-validation", "em-14-continuous-validation",
}

// POST /api/em/sweeps
// Creates a new Endpoint Mastery Full Sweep. Layers are resolved
// server-side by filtering emLayerIDs against the live scenario engine --
// never trusts a client-submitted list. Rejects (409) if the agent already
// has a running EM sweep.
func (h *Handler) CreateEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		AgentID string `json:"agentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	if h.engine == nil {
		jsonError(w, "scenario engine not loaded", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()

	var layers []string
	for _, id := range emLayerIDs {
		if _, ok := h.engine.Get(id); ok {
			layers = append(layers, id)
		}
	}
	if len(layers) == 0 {
		jsonError(w, "no EM layer scenarios loaded on the server", http.StatusUnprocessableEntity)
		return
	}

	c, _ := auth.ClaimsFrom(ctx)
	createdBy := ""
	if c != nil {
		createdBy = c.UserID
	}

	sw, err := h.emSweep.Create(ctx, emsweep.Sweep{
		AgentID: req.AgentID, Layers: layers, TotalLayers: len(layers), CreatedBy: createdBy,
	})
	if err != nil {
		if err == emsweep.ErrAgentAlreadySweeping {
			jsonError(w, "agent already has a running EM sweep", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "emsweep.create", sw.ID, map[string]any{"agentId": req.AgentID, "layerCount": len(layers)}, "ok")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, emSweepToJSON(sw))
}

// GET /api/em/sweeps/active?agentId=X
func (h *Handler) GetActiveEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	sw, found, err := h.emSweep.GetActiveForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "no active EM sweep for this agent", http.StatusNotFound)
		return
	}
	jsonOK(w, emSweepToJSON(sw))
}

// GET /api/em/sweeps/{id}
func (h *Handler) GetEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	sw, err := h.emSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}
	jsonOK(w, emSweepToJSON(sw))
}

// GET /api/em/sweeps/{id}/runs
func (h *Handler) GetEMSweepRuns(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	sw, err := h.emSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted
		 FROM scenario_runs WHERE em_sweep_id = $1 ORDER BY started_at`,
		id,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	runs, err := scanRunRows(rows)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []runRow{}
	}

	jsonOK(w, map[string]any{"sweep": emSweepToJSON(sw), "runs": runs})
}

// GET /api/em/sweeps?status=running
func (h *Handler) ListEMSweeps(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonOK(w, []map[string]any{})
		return
	}
	status := coalesce(strings.TrimSpace(r.URL.Query().Get("status")), "running")
	sweeps, err := h.emSweep.ListByStatus(r.Context(), status)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(sweeps))
	for _, sw := range sweeps {
		out = append(out, emSweepToJSON(sw))
	}
	jsonOK(w, out)
}

// POST /api/em/sweeps/{id}/cancel
func (h *Handler) CancelEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	sw, err := h.emSweep.Get(ctx, id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}
	if sw.Status != "running" {
		jsonError(w, "sweep is not running (status: "+sw.Status+")", http.StatusConflict)
		return
	}
	if sw.CurrentScenarioRunID != "" {
		if _, _, err := h.cancelScenarioRun(ctx, sw.CurrentScenarioRunID); err != nil && err != errRunNotRunning {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := h.emSweep.MarkStopped(ctx, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "emsweep.cancel", id, map[string]any{"agentId": sw.AgentID}, "ok")
	jsonOK(w, map[string]string{"id": id, "status": "stopped"})
}

func emSweepToJSON(sw emsweep.Sweep) map[string]any {
	return map[string]any{
		"id": sw.ID, "agentId": sw.AgentID, "layers": sw.Layers, "currentIndex": sw.CurrentIndex,
		"currentLayer": currentEMLayer(sw), "currentScenarioRunId": sw.CurrentScenarioRunID,
		"completedLayers": sw.CompletedLayers, "totalLayers": sw.TotalLayers,
		"status": sw.Status, "error": sw.Error, "createdBy": sw.CreatedBy,
		"startedAt": sw.StartedAt, "completedAt": sw.CompletedAt,
	}
}

func currentEMLayer(sw emsweep.Sweep) string {
	if sw.CurrentIndex >= 0 && sw.CurrentIndex < len(sw.Layers) {
		return sw.Layers[sw.CurrentIndex]
	}
	return ""
}

var _ = pgxpool.Pool{} // remove this line if pgxpool ends up unused after your edits -- present only if emSweepToJSON needs no live-progress DB query, unlike vexsweep's sweepToJSON
```

Delete that last `var _ = pgxpool.Pool{}` line and the `"github.com/jackc/pgx/v5/pgxpool"` import — `emSweepToJSON` here takes no `*pgxpool.Pool` argument (unlike vexsweep's `sweepToJSON`, which needs one for its live-progress `steps_done` peek; EM doesn't need that refinement per the spec's Non-Goals, since each layer is worth exactly 1, not a fractional variant count). Only keep imports actually used once the file is complete; run `go build` (Step 5) to catch any left over.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... 2>&1` (fix any unused-import errors first), then `go test ./internal/api/... -run "TestCreateEMSweep|TestGetActiveEMSweep|TestCancelEMSweep" -v 2>&1`

Expected: clean build, all 4 tests PASS.

- [ ] **Step 6: Add RBAC matrix entries**

Run: `grep -n '"/api/vex/sweeps' orchestrator/internal/api/rbac_matrix_test.go` to find the existing vexsweep entries in `routeMatrix`. Add 6 new entries immediately after them, using whatever tier constant (`tierPermission` + `perm: auth.CanRunScenario` / `auth.CanViewVariantRun` / `auth.CanCancelScenarioRun`, matching this task's route table above) this file's existing `routeMatrix` entries use for `tierPermission`-style rows — check one of the existing `auth.RequirePermission(...)`-gated rows in this same file for the exact `routeCase{}` shape to copy:

```go
	{http.MethodPost, "/api/em/sweeps", tierPermission, auth.CanRunScenario},
	{http.MethodGet, "/api/em/sweeps/active", tierPermission, auth.CanViewVariantRun},
	{http.MethodGet, "/api/em/sweeps/{id}", tierPermission, auth.CanViewVariantRun},
	{http.MethodGet, "/api/em/sweeps/{id}/runs", tierPermission, auth.CanViewVariantRun},
	{http.MethodGet, "/api/em/sweeps", tierPermission, auth.CanViewVariantRun},
	{http.MethodPost, "/api/em/sweeps/{id}/cancel", tierPermission, auth.CanCancelScenarioRun},
```

Confirmed exact shape (verified during plan-writing, `internal/api/rbac_matrix_test.go:201-206`): `{method, path, tierPermission, permission}` — the code above already matches this precisely, no adjustment needed.

- [ ] **Step 7: Register the routes**

In `orchestrator/internal/api/routes.go`, find the `vex/sweeps` block (`grep -n "vex/sweeps" internal/api/routes.go`) and add immediately after it:

```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/em/sweeps", h.CreateEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/active", h.GetActiveEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/{id}", h.GetEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/{id}/runs", h.GetEMSweepRuns)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps", h.ListEMSweeps)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/em/sweeps/{id}/cancel", h.CancelEMSweep)
```

- [ ] **Step 8: Run the RBAC drift test**

Run: `cd orchestrator && go test ./internal/api/... -run "TestRBACMatrix_NoDrift" -v 2>&1`

Expected: PASS. If it fails, the `routeMatrix` entries (Step 6) don't exactly match the routes.go registrations (Step 7) — reconcile method/path/permission until they match exactly.

- [ ] **Step 9: Run the FULL `internal/api` suite before committing**

Run in the background:

```bash
cd orchestrator && go test ./internal/api/... -timeout 20m > /tmp/em-task6-test.log 2>&1
```

Wait for real completion, read the full log file, confirm `ok`.

- [ ] **Step 10: Commit**

```bash
cd orchestrator
git add internal/api/emsweep_handlers.go internal/api/emsweep_handlers_test.go internal/api/rbac_matrix_test.go internal/api/routes.go
git commit -m "feat(api): add EM sweep HTTP handlers + routes + RBAC matrix entries"
git push
```

---

### Task 7: `cmd/server/main.go` wiring

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `emsweep.NewStore`, `emsweep.NewDispatcher` (Tasks 3-4), `h.WithEMSweep` (Task 5), `exercise.NewPollScheduler` (existing, already imported).
- Produces: a running EM sweep dispatcher ticking every 5 seconds in the live server process — this is what makes the whole feature actually work end-to-end, not just testable in isolation.

- [ ] **Step 1: Locate the exact insertion point**

Run: `grep -n "vexSweepStore\|vexSweepScheduler\|vexSweepDispatcher\|WithVexSweep" orchestrator/cmd/server/main.go`

Confirm the current line numbers for the `vexSweepStore`/`vexSweepScheduler`/`vexSweepDispatcher` construction block, the `.WithVexSweep(...)` call inside the `.With*` chain, and the `vexSweepScheduler.Start(...)` / `defer vexSweepScheduler.Stop()` pair.

- [ ] **Step 2: Add the EM sweep store/scheduler/dispatcher construction**

Immediately after the `vexSweepDispatcher := vexsweep.NewDispatcher(...)` block, add:

```go
	// Endpoint Mastery Full Sweep — same server-owned orchestration pattern
	// as Full Variant Sweep, ticking every 5s.
	emSweepStore := emsweep.NewStore(pool)
	emSweepScheduler := exercise.NewPollScheduler(5 * time.Second)
	emSweepDispatcher := emsweep.NewDispatcher(emSweepStore, func(ctx context.Context, scenarioRunID string) (string, error) {
		var status string
		err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = $1`, scenarioRunID).Scan(&status)
		return status, err
	})
```

Add `"github.com/audspect/bas/internal/emsweep"` to this file's import block.

- [ ] **Step 3: Add `.WithEMSweep(...)` to the handler chain**

Find the `.WithVexSweep(vexSweepStore, vexSweepDispatcher).` line in the `handler := api.New(...)` chain and add immediately after it:

```go
		WithEMSweep(emSweepStore, emSweepDispatcher).
```

- [ ] **Step 4: Start and stop the scheduler**

Immediately after the existing `vexSweepScheduler.Start(...)` / `defer vexSweepScheduler.Stop()` pair, add:

```go
	emSweepScheduler.Start(func(ctx context.Context) {
		if err := emSweepDispatcher.Tick(ctx); err != nil {
			log.Printf("[emsweep] tick: %v", err)
		}
	})
	defer emSweepScheduler.Stop()
```

- [ ] **Step 5: Verify it builds**

Run: `cd orchestrator && go build ./... 2>&1`

Expected: no output.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add cmd/server/main.go
git commit -m "feat(server): wire up EM sweep store/dispatcher/scheduler"
git push
```

---

### Task 8: Frontend — replace `runEmSweep()` with a target-picker modal + fan-out dispatch

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
  - Delete: `runEmSweep()` (currently `:17812-17835`)
  - Modify: the "Run Full Sweep" button (currently `:3789`) to open the new modal instead of calling `runEmSweep()` directly
  - Add: new modal markup (a new `<div id="em-sweep-overlay" class="drawer-overlay">...` or similar, placed near the existing `#run-live-overlay`/`#sweep-drilldown-overlay` markup around `:4321-4347`), a new target-mode picker (Individual/Group(s)/All Agents) closely modeled on `vexRunFullSweep()`'s existing markup/logic (`:17077-17145`) but with its own IDs/functions (no shared DOM elements or JS functions with the vex-sweep flow, per the spec's explicit decision)
  - Add: new JS functions `openEMSweepModal()`, `emSweepRunSingleAgent()`, `emSweepRunGroupOrAll()` (names illustrative — pick whatever reads clearly, just keep them EM-prefixed and distinct from the `vex*` names)

**Interfaces:**
- Consumes: `resolveGroupTargetAgents` and `gpFlattenGroups` (existing shared helpers, `:7090-7098` and `:7054-7062`), `agentGroupTree` (existing global, populated at boot by `loadAgentGroupTree()`), `POST /api/em/sweeps` (Task 6). Own new state: `_emGroupSel`, `_emTargetMode` (EM-prefixed, deliberately not reusing `_vex*` globals — see spec's "duplicate and adapt, don't share" decision).
- Produces: the new modal + dispatch flow Task 9's drawer opens into after a sweep starts.

- [ ] **Step 1: Confirm which existing patterns to model against**

Two different existing things get mirrored here, confirmed during plan-writing — don't conflate them:

- **Group-mode resolution**: `vexRunFullSweep`'s group branch (`wwwroot/index.html:17087-17130`) uses `resolveGroupTargetAgents(selectedGroupIds)` (`:7090-7098`, recurses into subgroups via `buildGroupDescendantMap`) and `gpFlattenGroups` (`:7054-7062`, the shared checkbox-list flattening helper). Reuse both directly — they're already generic, not vexsweep-specific.
- **3-mode (Individual/Group/All) UI pattern**: `vexRunFullSweep` itself only has 2 modes (`_vexTargetMode` is `'individual' | 'group'`, confirmed via `wwwroot/index.html:17005`; no "All Agents" branch exists in that function). The 3-mode radio pattern actually being modeled here is the Run Scenario modal's `modal-target-mode` (`grep -n "modal-target-mode" wwwroot/index.html` to see it) — a separate, correctly-3-mode picker. EM Sweep's "All Agents" mode resolves simply as every currently-online agent (`agents.filter(a => a.status === 'online')`, already written into Step 5's code below) rather than reusing `resolvedAllTargetIds()` (that helper requires a single scenario object for OS-eligibility filtering, which doesn't apply here — an EM sweep dispatches 14 different scenarios, each individually OS-gated server-side by `dispatchRun` at actual dispatch time, not something the frontend needs to pre-filter for).

Also read `:3788-3789` for the exact current "Run Full Sweep" button markup.

- [ ] **Step 2: Add the new modal markup**

Near the existing `#run-live-overlay`/`#sweep-drilldown-overlay` drawer markup (`:4321-4347`), add a new overlay:

```html
<!-- Endpoint Mastery Full Sweep: target picker -->
<div id="em-sweep-modal-overlay" class="drawer-overlay" onclick="if(event.target===this)closeEMSweepModal()">
  <div class="drawer" style="width:480px;max-width:94vw">
    <div class="drawer-header">
      <h3>Run Full Sweep — Endpoint Mastery</h3>
      <button class="drawer-close" onclick="closeEMSweepModal()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <p class="tiny muted" style="margin-bottom:0.75rem">Dispatches all 14 Endpoint Mastery layers sequentially — each layer runs to completion before the next starts.</p>
      <div class="form-group">
        <label style="display:flex;align-items:center;gap:0.4rem;margin-bottom:0.3rem">
          <input type="radio" name="em-sweep-target-mode" value="individual" checked onchange="setEMSweepTargetMode('individual')"> Individual Agent
        </label>
        <label style="display:flex;align-items:center;gap:0.4rem;margin-bottom:0.3rem">
          <input type="radio" name="em-sweep-target-mode" value="group" onchange="setEMSweepTargetMode('group')"> Agent Group(s)
        </label>
        <label style="display:flex;align-items:center;gap:0.4rem;margin-bottom:0.75rem">
          <input type="radio" name="em-sweep-target-mode" value="all" onchange="setEMSweepTargetMode('all')"> All Agents
        </label>
      </div>
      <div id="em-sweep-individual-wrap">
        <label class="modal-lbl">Agent</label>
        <select id="em-sweep-agent" style="width:100%;padding:0.5rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text)"></select>
      </div>
      <div id="em-sweep-group-wrap" style="display:none">
        <div id="em-sweep-group-list" style="max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.5rem"></div>
      </div>
      <div style="margin-top:1rem;display:flex;justify-content:flex-end;gap:0.5rem">
        <button class="btn btn-outline btn-sm" onclick="closeEMSweepModal()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="emSweepDispatch()">&#9654; Start Sweep</button>
      </div>
    </div>
  </div>
</div>
```

This markup is illustrative in exact styling — match this file's existing modal/drawer CSS classes and conventions (`.drawer-overlay`, `.drawer`, `.drawer-header`, `.drawer-body`, `.form-group`, `.modal-lbl` — confirm these class names actually exist and are styled as expected by grepping their CSS definitions first) rather than copying verbatim if the real classes differ slightly.

- [ ] **Step 3: Repoint the "Run Full Sweep" button**

Change `:3789` from:

```html
<button class="btn btn-primary btn-sm" onclick="runEmSweep()">&#9654; Run Full Sweep</button>
```

to:

```html
<button class="btn btn-primary btn-sm" onclick="openEMSweepModal()">&#9654; Run Full Sweep</button>
```

- [ ] **Step 4: Delete `runEmSweep()`**

Delete the entire `runEmSweep()` function currently at `:17812-17835`.

- [ ] **Step 5: Write the new JS**

Add near where `runEmSweep()` used to be:

```js
// ── Endpoint Mastery Full Sweep ─────────────────────────────────────────
// Own target-mode state, deliberately not shared with _vexTargetMode/
// _vexGroupSel -- see design spec's "duplicate and adapt, don't share"
// decision (docs/superpowers/specs/2026-08-13-em-full-sweep-design.md).
var _emTargetMode = 'individual';
var _emGroupSel = {};

function openEMSweepModal() {
  if (!agents.length) { showToast('No agents enrolled.', 'err'); showTab('agents'); return; }
  _emTargetMode = 'individual';
  _emGroupSel = {};
  document.querySelector('input[name="em-sweep-target-mode"][value="individual"]').checked = true;
  document.getElementById('em-sweep-individual-wrap').style.display = '';
  document.getElementById('em-sweep-group-wrap').style.display = 'none';
  var sel = document.getElementById('em-sweep-agent');
  sel.innerHTML = agents.map(function(a) {
    return '<option value="' + x(a.agentId) + '">' + x(a.agentId) + ' — ' + x(a.hostname) + '</option>';
  }).join('');
  renderEMSweepGroupList(); // agentGroupTree is already loaded at boot by loadAgentGroupTree() -- no fresh fetch needed
  document.getElementById('em-sweep-modal-overlay').classList.add('open');
}

// renderEMSweepGroupList mirrors renderVexGroupList (:17036-17057) exactly:
// gpFlattenGroups is the same shared tree-flattening helper the Run
// Scenario wizard's own Group(s) mode and vexRunFullSweep's group mode
// both already use.
function renderEMSweepGroupList() {
  var list = document.getElementById('em-sweep-group-list');
  if (!list) return;
  var options = gpFlattenGroups(agentGroupTree, 0, null, []);
  if (!options.length) {
    list.innerHTML = '<p class="tiny muted" style="margin:0">No agent groups have been created yet.</p>';
    return;
  }
  list.innerHTML = options.map(function(o) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (_emGroupSel[o.id] ? 'checked' : '') +
      ' onchange="_emGroupSel[' + o.id + ']=this.checked">' +
      '<span style="font-size:0.8rem">' + x(o.label) + '</span></label>';
  }).join('');
}

function closeEMSweepModal() {
  document.getElementById('em-sweep-modal-overlay').classList.remove('open');
}

function setEMSweepTargetMode(mode) {
  _emTargetMode = mode;
  document.getElementById('em-sweep-individual-wrap').style.display = mode === 'individual' ? '' : 'none';
  document.getElementById('em-sweep-group-wrap').style.display = mode === 'group' ? '' : 'none';
}

// emResolvedGroupAgents resolves the currently-checked groups to their
// member agents via resolveGroupTargetAgents (:7090-7098) -- the same
// pre-existing, already-correct helper vexResolvedGroupAgents (:17063-17066)
// uses, which recurses into subgroups via buildGroupDescendantMap. Do not
// reimplement group flattening here.
function emResolvedGroupAgents() {
  var selectedGroupIds = Object.keys(_emGroupSel).filter(function(k) { return _emGroupSel[k]; }).map(Number);
  return resolveGroupTargetAgents(selectedGroupIds);
}

function emSweepDispatch() {
  var targets = [];
  if (_emTargetMode === 'individual') {
    var agentId = document.getElementById('em-sweep-agent').value;
    if (!agentId) { showToast('Select an agent', 'err'); return; }
    targets = [agentId];
  } else if (_emTargetMode === 'group') {
    var resolved = emResolvedGroupAgents();
    if (!resolved.length) { showToast('Select at least one group with agents', 'err'); return; }
    targets = resolved.map(function(a) { return a.agentId; });
  } else {
    targets = (agents || []).filter(function(a) { return a.status === 'online'; }).map(function(a) { return a.agentId; });
    if (!targets.length) { showToast('No online agents', 'err'); return; }
  }

  if (!confirm('Start Endpoint Mastery Full Sweep on ' + targets.length + ' agent(s)?\n\nEach agent runs all 14 layers sequentially — this may take a while per agent.\n\nContinue?')) return;

  closeEMSweepModal();
  var dispatches = targets.map(function(agentId) {
    return apicall('/api/em/sweeps', {
      method: 'POST',
      body: JSON.stringify({ agentId: agentId })
    }).then(function(res) {
      if (res && res.error) return { agentId: agentId, ok: false, error: res.error };
      return { agentId: agentId, ok: true };
    }).catch(function(e) {
      return { agentId: agentId, ok: false, error: e.message };
    });
  });

  Promise.all(dispatches).then(function(results) {
    var ok = results.filter(function(r) { return r.ok; });
    var failed = results.filter(function(r) { return !r.ok; });
    if (!failed.length) {
      showToast('Started ' + ok.length + ' EM sweep(s).', 'ok');
    } else if (ok.length) {
      showToast('Started ' + ok.length + '/' + results.length + ' sweeps. Failed: ' +
        failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
    } else {
      showToast('All ' + results.length + ' sweep dispatches failed. ' +
        failed.map(function(f) { return f.agentId + ' (' + f.error + ')'; }).join(', '), 'err');
    }
    showTab('runs');
  });
}
```

- [ ] **Step 6: Verify JS syntax**

Use this session's established extraction convention. Write a small Node script to the scratchpad directory extracting every `<script>` block from `index.html`, concatenate, then run `node --check` on the result via the PowerShell tool (Windows `node.exe` misresolves Bash's `/c/...`-style paths — this must run via PowerShell, not Bash):

```powershell
node "<scratchpad>\extract_scripts.js"; node --check "<scratchpad>\extracted.js"
```

(Reuse the extraction script from earlier in this session if it still exists in the scratchpad directory; otherwise write a short Node script that regex-matches `<script(?:\s+[^>]*)?>([\s\S]*?)<\/script>` across the file, concatenates each match with a `;` separator, and writes the result to `extracted.js`.)

Expected: no output (clean syntax).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): replace EM Run Full Sweep with a real target picker + server-orchestrated dispatch"
git push
```

---

### Task 9: Frontend — live progress drawer

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
  - Add: a new drawer (e.g. `#em-sweep-progress-overlay`) listing a sweep's layers with status pills
  - Add: JS to poll `GET /api/em/sweeps/{id}` and render it
  - Modify: `emSweepDispatch()` (Task 8) to open this drawer for the first successfully-dispatched sweep (or, if multiple agents were targeted, offer a way to pick which one to watch — simplest: after a group/all-agents dispatch, don't auto-open the drawer, just show the toast and rely on Live Runs' `em_sweep_id` grouping; only auto-open for the single-agent case)

**Interfaces:**
- Consumes: `GET /api/em/sweeps/{id}` (Task 6), the sweep JSON shape from `emSweepToJSON` (`id, agentId, layers, currentIndex, currentLayer, currentScenarioRunId, completedLayers, totalLayers, status, error, createdBy, startedAt, completedAt`).

- [ ] **Step 1: Add the drawer markup**

Near the modal added in Task 8:

```html
<!-- Endpoint Mastery Full Sweep: live progress -->
<div id="em-sweep-progress-overlay" class="drawer-overlay" onclick="if(event.target===this)closeEMSweepProgress()">
  <div class="drawer" style="width:480px;max-width:94vw">
    <div class="drawer-header">
      <h3 id="em-sweep-progress-title">EM Full Sweep — Live</h3>
      <button class="drawer-close" onclick="closeEMSweepProgress()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="em-sweep-progress-summary" style="margin-bottom:0.75rem"></div>
      <ul id="em-sweep-progress-list" style="list-style:none;margin:0;padding:0"></ul>
      <div style="margin-top:1rem;display:flex;justify-content:flex-end">
        <button class="btn btn-outline-red btn-sm" id="em-sweep-stop-btn" onclick="stopEMSweep()">&#9632; Stop Sweep</button>
      </div>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Write the polling/render JS**

```js
var _emSweepPollTimer = null;
var _emSweepCurrentId = null;

function openEMSweepProgress(sweepId) {
  _emSweepCurrentId = sweepId;
  document.getElementById('em-sweep-progress-overlay').classList.add('open');
  pollEMSweepProgress();
  if (_emSweepPollTimer) clearInterval(_emSweepPollTimer);
  _emSweepPollTimer = setInterval(pollEMSweepProgress, 3000);
}

function closeEMSweepProgress() {
  document.getElementById('em-sweep-progress-overlay').classList.remove('open');
  if (_emSweepPollTimer) { clearInterval(_emSweepPollTimer); _emSweepPollTimer = null; }
  _emSweepCurrentId = null;
}

function pollEMSweepProgress() {
  if (!_emSweepCurrentId) return;
  apicall('/api/em/sweeps/' + encodeURIComponent(_emSweepCurrentId)).then(function(sw) {
    if (!sw || sw.error) return;
    renderEMSweepProgress(sw);
    if (sw.status !== 'running' && _emSweepPollTimer) {
      clearInterval(_emSweepPollTimer);
      _emSweepPollTimer = null;
    }
  }).catch(function() {});
}

function renderEMSweepProgress(sw) {
  document.getElementById('em-sweep-progress-title').textContent = 'EM Full Sweep — ' + x(sw.agentId);
  document.getElementById('em-sweep-progress-summary').innerHTML =
    '<strong>' + sw.completedLayers + '/' + sw.totalLayers + '</strong> layers complete &middot; status: ' + x(sw.status) +
    (sw.error ? '<div style="color:var(--danger);margin-top:0.3rem">' + x(sw.error) + '</div>' : '');
  var list = document.getElementById('em-sweep-progress-list');
  list.innerHTML = (sw.layers || []).map(function(layerId, i) {
    var state = i < sw.currentIndex ? 'done' : (i === sw.currentIndex && sw.status === 'running') ? 'running' : 'pending';
    var color = state === 'done' ? 'var(--success)' : state === 'running' ? 'var(--accent)' : 'var(--muted)';
    var label = state === 'done' ? '&#10003;' : state === 'running' ? '&#9679;' : '&#9675;';
    return '<li style="display:flex;align-items:center;gap:0.5rem;padding:0.3rem 0;color:' + color + '">' +
      '<span>' + label + '</span><span>' + x(layerId) + '</span></li>';
  }).join('');
  var stopBtn = document.getElementById('em-sweep-stop-btn');
  stopBtn.style.display = sw.status === 'running' ? '' : 'none';
}

function stopEMSweep() {
  if (!_emSweepCurrentId) return;
  if (!confirm('Stop this EM sweep? The current layer keeps running to completion but no further layers will be dispatched.')) return;
  apicall('/api/em/sweeps/' + encodeURIComponent(_emSweepCurrentId) + '/cancel', { method: 'POST' }).then(function() {
    pollEMSweepProgress();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 3: Wire single-agent dispatch to auto-open the drawer**

In `emSweepDispatch()` (Task 8), find the `Promise.all(dispatches).then(function(results) {...})` block. Add, right before the final `showTab('runs');` line:

```js
    if (targets.length === 1 && ok.length === 1) {
      apicall('/api/em/sweeps/active?agentId=' + encodeURIComponent(targets[0])).then(function(sw) {
        if (sw && sw.id) openEMSweepProgress(sw.id);
      }).catch(function() {});
    }
```

- [ ] **Step 4: Verify JS syntax**

Same extraction + `node --check` convention as Task 8 Step 6.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): add live progress drawer for EM Full Sweep"
git push
```

---

### Task 10: Full verification + final full-suite run

**Files:** none new — this task only runs verification across everything Tasks 1-9 touched.

**Interfaces:** none — this is the final gate before considering the feature done.

- [ ] **Step 1: Full backend build**

Run: `cd orchestrator && go build ./... 2>&1`

Expected: no output.

- [ ] **Step 2: Full `internal/emsweep` suite**

Run: `cd orchestrator && go test ./internal/emsweep/... -v 2>&1`

Expected: every test PASS.

- [ ] **Step 3: Full `internal/api` suite (background, real log check)**

```bash
cd orchestrator && go test ./internal/api/... -timeout 20m > /tmp/em-final-test.log 2>&1
```

Run with `run_in_background: true`. Wait for the real completion notification. Then read the actual file (`tail -n 15 /tmp/em-final-test.log`) — do not trust any earlier piped/truncated view. Confirm it ends with `ok  	github.com/audspect/bas/internal/api	<N>s`.

- [ ] **Step 4: Full JS syntax check**

Re-run the extraction + `node --check` convention on the final state of `wwwroot/index.html` (via PowerShell, not Bash).

Expected: no output.

- [ ] **Step 5: RBAC drift check (redundant safety net)**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v 2>&1`

Expected: PASS.

- [ ] **Step 6: Report manual QA items to the user**

This plan cannot verify these without a live browser + deployed server (same constraint noted throughout this session for every frontend change). At the end of implementation, tell the user explicitly that these need manual verification once deployed, copied directly from the spec's "Manual QA" section:

- Start an EM sweep against a single agent; confirm all (up to) 14 layers actually dispatch in sequence, not just the first.
- Start an EM sweep via Group(s) and via All Agents; confirm one independent sweep per resolved agent.
- Close the browser tab mid-sweep, reopen, confirm the sweep is still progressing server-side and the drawer can reattach to it.
- Force a layer to hang (or wait for a real one) past 3 minutes; confirm force-cancel-and-advance fires.
- Confirm Live Runs collapses a sweep's layer-runs into one row via `em_sweep_id`, matching Full Variant Sweep's existing behavior.

Also remind the user this needs an orchestrator rebuild + redeploy to take effect (same as every other backend/frontend change this session).

- [ ] **Step 7: Final commit if anything is outstanding**

If Steps 1-5 required any fixes not yet committed, commit and push them now with a message describing what was fixed. If everything was already green and committed task-by-task, this step is a no-op — just confirm `git status` is clean and `git log` shows the full sequence of commits from Tasks 1-9 pushed to `main`.
