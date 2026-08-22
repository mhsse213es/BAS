# Initiative Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Group related `Job` rows (possibly of different types) into a `Initiative` with an explicit `active → closed → archived` lifecycle and derived progress, so a multi-stage operation (assessment → remediation → revalidation) has one auditable identity instead of unrelated `Job` rows with no link between them.

**Architecture:** New sibling package `internal/initiatives` mirrors `internal/jobs`'s shape exactly (plain `Store` over `*pgxpool.Pool`, no cross-package imports, no business rules beyond its own lifecycle funnel). `internal/jobs` gains one additive plumbing method (`SetJobInitiative`) and one additive column (`jobs.initiative_id`). `internal/api/initiative_handlers.go` is the new integration layer — it alone enforces "only an active initiative accepts new members," mirroring `job_dispatch.go`'s existing role gluing `internal/jobs` to `internal/remediation`/`internal/notifications`.

**Tech Stack:** Go, chi router, pgxpool (Postgres), testcontainers-go for package tests.

**Spec:** `docs/superpowers/specs/2026-08-22-initiative-layer-design.md` (this plan implements it in full; read it first for the "why" behind every decision below).

## Global Constraints

- `initiatives.id` and every other new/touched ID column uses `text PRIMARY KEY DEFAULT gen_random_uuid()::text`, matching `jobs.id`/`job_targets.id` exactly (see `internal/db/postgres.go:1369`).
- No FK constraints on `jobs.initiative_id` — matches the existing unconstrained-text convention for `requested_by`/`approved_by`/`created_by`/`owner_id` elsewhere in this schema.
- `Progress.PercentComplete` is `float64`, matching `jobs.JobProgress.PercentComplete`'s existing type exactly (see `internal/jobs/progress.go:15`).
- Lifecycle funnel is strictly forward-only: `active → closed → archived`. No reverse transition exists anywhere in this plan.
- All 6 new HTTP endpoints are gated by `auth.RequirePermission(auth.CanExecuteRemediation)` — no new permission is introduced.
- Every membership/lifecycle-changing handler calls the existing `h.auditLog(r, action, resource, detail, outcome)` helper (`internal/api/audit.go:49`) — no new audit mechanism.
- Package tests use the existing `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` container-test harness already used throughout `internal/jobs`'s own test files (see `internal/jobs/progress_test.go`) — every container-backed test starts with `if testing.Short() { t.Skip(...) }`.
- Handler tests construct the handler via `New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))` — the exact pattern in `internal/api/job_target_handlers_test.go`.
- Run each affected package's full test suite (not just new tests) before every commit; commit after each logically-complete task; `git push` immediately after every commit (this repo builds directly on `main`, no branches/PRs).

---

## Task 1: `initiatives` table + `jobs.initiative_id` column (migration)

**Files:**
- Modify: `internal/db/postgres.go` (append to the migration statement list — find the existing `jobs`/`job_targets` `CREATE TABLE` block around line 1368 and add immediately after it, following that exact style)

**Interfaces:**
- Produces: the `initiatives` table and `jobs.initiative_id` column that every later task's SQL depends on.

- [ ] **Step 1: Read the exact surrounding style**

Read `internal/db/postgres.go` lines 1360-1400 to confirm the exact indentation/backtick-string style used for the `jobs`/`job_targets` table definitions and their trailing `CREATE INDEX` lines, so the new statements match exactly.

- [ ] **Step 2: Add the migration statements**

Immediately after the existing `job_targets` table's `CREATE INDEX` lines (the two lines ending `internal/db/postgres.go:1394`), insert:

```go
		`CREATE TABLE IF NOT EXISTS initiatives (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name          text        NOT NULL,
			description   text        NOT NULL DEFAULT '',
			state         text        NOT NULL DEFAULT 'active',
			created_by    text        NOT NULL DEFAULT '',
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			closed_at     timestamptz,
			archived_at   timestamptz
		)`,
		`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS initiative_id text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_initiative_id ON jobs (initiative_id) WHERE initiative_id <> ''`,
```

- [ ] **Step 3: Verify the package builds**

Run: `go build ./internal/db/...`
Expected: no errors.

- [ ] **Step 4: Verify the migration runs clean against a real container**

Run (background, since it spins up testcontainers):
```bash
go test ./internal/db/... -run TestMigrate -v
```
If no test named `TestMigrate` exists, instead run any existing `internal/db` package test (e.g. `go test ./internal/db/...`) — the migration list runs as part of every package's `sharedDB` setup, so any passing test in any package confirms the new statements are syntactically valid. Read the actual log after the run completes (do not trust a piped/truncated capture).
Expected: PASS, no SQL syntax errors.

- [ ] **Step 5: Commit**

```bash
git add internal/db/postgres.go
git commit -m "feat(db): add initiatives table and jobs.initiative_id column

Additive migration for the Initiative layer -- groups related Job rows
into one auditable security initiative. No FK constraint on
initiative_id, matching the existing unconstrained-text convention for
owner_id/created_by elsewhere in this schema."
git push
```

---

## Task 2: `internal/initiatives` package — `Store.Create`/`Get`/`List`

**Files:**
- Create: `internal/initiatives/types.go`
- Create: `internal/initiatives/store.go`
- Create: `internal/initiatives/store_test.go`

**Interfaces:**
- Consumes: the `initiatives` table from Task 1.
- Produces:
  ```go
  type Initiative struct {
      ID          string
      Name        string
      Description string
      State       string // active | closed | archived
      CreatedBy   string
      CreatedAt   time.Time
      ClosedAt    *time.Time
      ArchivedAt  *time.Time
  }
  const (
      StateActive   = "active"
      StateClosed   = "closed"
      StateArchived = "archived"
  )
  func NewStore(pool *pgxpool.Pool) *Store
  func (s *Store) Create(ctx context.Context, name, description, createdBy string) (Initiative, error)
  func (s *Store) Get(ctx context.Context, id string) (Initiative, error)
  func (s *Store) List(ctx context.Context, state string) ([]Initiative, error)
  ```
  Later tasks (Close/Archive/ComputeProgress, and `internal/api`) depend on these exact names and signatures.

- [ ] **Step 1: Write `types.go`**

```go
// Package initiatives is generic infrastructure for grouping related
// internal/jobs.Job rows -- possibly of different types -- into one
// auditable security initiative with an explicit lifecycle and derived
// progress. It knows nothing about what any Job.Type actually does; that
// stays entirely in internal/jobs and internal/api. See
// docs/superpowers/specs/2026-08-22-initiative-layer-design.md.
package initiatives

import "time"

const (
	StateActive   = "active"
	StateClosed   = "closed"
	StateArchived = "archived"
)

// Initiative is a named security initiative that groups one or more Jobs.
type Initiative struct {
	ID          string
	Name        string
	Description string
	State       string
	CreatedBy   string
	CreatedAt   time.Time
	ClosedAt    *time.Time
	ArchivedAt  *time.Time
}
```

- [ ] **Step 2: Write the failing test for `Create`/`Get`/`List`**

```go
package initiatives

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateGet_RoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		created, err := store.Create(ctx, "Q3 Patch Compliance", "quarterly patch push", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.ID == "" {
			t.Fatal("Create: expected a generated ID")
		}
		if created.State != StateActive {
			t.Errorf("State = %q, want %q", created.State, StateActive)
		}

		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Name != "Q3 Patch Compliance" || got.Description != "quarterly patch push" || got.CreatedBy != "user-1" {
			t.Errorf("got = %+v, want the values passed to Create", got)
		}
	})
}

func TestList_FiltersByState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		a, err := store.Create(ctx, "list-a", "", "user-1")
		if err != nil {
			t.Fatalf("Create a: %v", err)
		}
		b, err := store.Create(ctx, "list-b", "", "user-1")
		if err != nil {
			t.Fatalf("Create b: %v", err)
		}
		if _, err := store.Close(ctx, b.ID); err != nil {
			t.Fatalf("Close b: %v", err)
		}

		active, err := store.List(ctx, StateActive)
		if err != nil {
			t.Fatalf("List(active): %v", err)
		}
		foundA, foundB := false, false
		for _, it := range active {
			if it.ID == a.ID {
				foundA = true
			}
			if it.ID == b.ID {
				foundB = true
			}
		}
		if !foundA || foundB {
			t.Errorf("List(active) = %+v, want a present and b absent", active)
		}

		all, err := store.List(ctx, "")
		if err != nil {
			t.Fatalf("List(\"\"): %v", err)
		}
		if len(all) < 2 {
			t.Errorf("List(\"\") returned %d rows, want at least 2", len(all))
		}
	})
}
```

Note: this test file calls `store.Close`, which doesn't exist yet — that's expected, it's written in Task 3. For this step, comment out or temporarily omit the `TestList_FiltersByState` test body's `Close` call and just test `Create`+`Get` alone; the full test as written above is the target once Task 3 lands. Concretely: write `TestCreateGet_RoundTrips` now (Step 2 of this task), and defer `TestList_FiltersByState` to Task 3 Step 2 where `Close` exists. Only `TestCreateGet_RoundTrips` goes in `store_test.go` in this task.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/initiatives/... -run TestCreateGet_RoundTrips -v`
Expected: FAIL — `NewStore`/`Create`/`Get` undefined.

- [ ] **Step 4: Write `store.go`**

```go
package initiatives

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const initiativeColumns = `id, name, description, state, created_by, created_at, closed_at, archived_at`

func scanInitiative(row pgx.Row) (Initiative, error) {
	var it Initiative
	err := row.Scan(&it.ID, &it.Name, &it.Description, &it.State, &it.CreatedBy, &it.CreatedAt, &it.ClosedAt, &it.ArchivedAt)
	return it, err
}

// Create makes a new Initiative in StateActive.
func (s *Store) Create(ctx context.Context, name, description, createdBy string) (Initiative, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO initiatives (name, description, state, created_by) VALUES ($1,$2,$3,$4)
		 RETURNING `+initiativeColumns,
		name, description, StateActive, createdBy)
	return scanInitiative(row)
}

func (s *Store) Get(ctx context.Context, id string) (Initiative, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+initiativeColumns+` FROM initiatives WHERE id=$1`, id)
	return scanInitiative(row)
}

// List returns every Initiative, optionally narrowed to one state
// ("" means every state), newest first.
func (s *Store) List(ctx context.Context, state string) ([]Initiative, error) {
	var rows pgx.Rows
	var err error
	if state == "" {
		rows, err = s.pool.Query(ctx, `SELECT `+initiativeColumns+` FROM initiatives ORDER BY created_at DESC`)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT `+initiativeColumns+` FROM initiatives WHERE state=$1 ORDER BY created_at DESC`, state)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Initiative
	for rows.Next() {
		it, err := scanInitiative(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
```

`pgx.Row` and `pgx.Rows` (from `github.com/jackc/pgx/v5`, already a project dependency) both satisfy `Scan(dest ...any) error`, so `scanInitiative` accepts either a single-row `QueryRow` result or a `Rows` cursor mid-iteration — the same shared-scan-helper pattern `internal/jobs` uses via `scanJobTargets`.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/initiatives/... -run TestCreateGet_RoundTrips -v`
Expected: PASS. If a compile error about the `rows` interface appears, apply the `pgx.Rows` fix noted in Step 4 and re-run.

- [ ] **Step 6: Commit**

```bash
git add internal/initiatives/types.go internal/initiatives/store.go internal/initiatives/store_test.go
git commit -m "feat(initiatives): add Store.Create/Get/List

New internal/initiatives package, mirrors internal/jobs's Store shape.
Foundation for the Initiative layer -- lifecycle (Close/Archive) and
ComputeProgress land in the next two tasks."
git push
```

---

## Task 3: `Store.Close`/`Store.Archive` — lifecycle funnel

**Files:**
- Modify: `internal/initiatives/store.go`
- Modify: `internal/initiatives/store_test.go` (add the deferred `TestList_FiltersByState` from Task 2, plus new lifecycle tests)

**Interfaces:**
- Consumes: `Store`, `Initiative`, `StateActive`/`StateClosed`/`StateArchived` from Task 2.
- Produces:
  ```go
  func (s *Store) Close(ctx context.Context, id string) (Initiative, error)
  func (s *Store) Archive(ctx context.Context, id string) (Initiative, error)
  ```
  Both return a sentinel error `ErrInvalidTransition` when the funnel is violated — `internal/api` (Task 5) checks `errors.Is(err, initiatives.ErrInvalidTransition)` to return 409.

- [ ] **Step 1: Add the now-unblocked `TestList_FiltersByState` from Task 2**

Add the full `TestList_FiltersByState` test body (as written in Task 2 Step 2, including the `store.Close(ctx, b.ID)` call) to `store_test.go`.

- [ ] **Step 2: Write the failing tests for the funnel**

Append to `store_test.go`:

```go
func TestClose_RejectsNonActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		it, err := store.Create(ctx, "close-twice", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := store.Close(ctx, it.ID); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		if _, err := store.Close(ctx, it.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("second Close: err = %v, want ErrInvalidTransition", err)
		}
	})
}

func TestArchive_RequiresClosedFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		it, err := store.Create(ctx, "archive-from-active", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := store.Archive(ctx, it.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("Archive from active: err = %v, want ErrInvalidTransition", err)
		}

		if _, err := store.Close(ctx, it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		archived, err := store.Archive(ctx, it.ID)
		if err != nil {
			t.Fatalf("Archive after Close: %v", err)
		}
		if archived.State != StateArchived {
			t.Errorf("State = %q, want %q", archived.State, StateArchived)
		}
		if archived.ArchivedAt == nil {
			t.Error("ArchivedAt is nil, want set")
		}
	})
}
```

Add `"errors"` to the test file's imports.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/initiatives/... -run 'TestClose_RejectsNonActive|TestArchive_RequiresClosedFirst|TestList_FiltersByState' -v`
Expected: FAIL — `Close`/`Archive`/`ErrInvalidTransition` undefined.

- [ ] **Step 4: Implement `Close`/`Archive`**

Add to `store.go`:

```go
import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrInvalidTransition is returned when Close or Archive is called on an
// Initiative not currently in the state that transition requires.
var ErrInvalidTransition = errors.New("invalid initiative state transition")

// Close moves an Initiative from active to closed. Requires the current
// state to be active.
func (s *Store) Close(ctx context.Context, id string) (Initiative, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE initiatives SET state=$1, closed_at=NOW() WHERE id=$2 AND state=$3
		 RETURNING `+initiativeColumns,
		StateClosed, id, StateActive)
	it, err := scanInitiative(row)
	if err != nil {
		if isNoRows(err) {
			return Initiative{}, ErrInvalidTransition
		}
		return Initiative{}, err
	}
	return it, nil
}

// Archive moves an Initiative from closed to archived. Requires the
// current state to be closed.
func (s *Store) Archive(ctx context.Context, id string) (Initiative, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE initiatives SET state=$1, archived_at=NOW() WHERE id=$2 AND state=$3
		 RETURNING `+initiativeColumns,
		StateArchived, id, StateClosed)
	it, err := scanInitiative(row)
	if err != nil {
		if isNoRows(err) {
			return Initiative{}, ErrInvalidTransition
		}
		return Initiative{}, err
	}
	return it, nil
}
```

Add a small helper (also in `store.go`) distinguishing "no such id at all" from "id exists but wrong state" is not needed for V1 — both collapse to `ErrInvalidTransition` per the spec's error-handling table treating both as 409-worthy from the funnel's perspective; `internal/api` (Task 5) handles the "id doesn't exist at all" 404 case separately via a preceding `Get` call, so `Close`/`Archive`'s own `UPDATE ... WHERE ... AND state=...` returning zero rows is unambiguous by the time it's reached. Add:

```go
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
```

Add `"github.com/jackc/pgx/v5"` to the imports for `pgx.ErrNoRows`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/initiatives/... -v`
Expected: PASS for every test in the package so far (`TestCreateGet_RoundTrips`, `TestList_FiltersByState`, `TestClose_RejectsNonActive`, `TestArchive_RequiresClosedFirst`).

- [ ] **Step 6: Commit**

```bash
git add internal/initiatives/store.go internal/initiatives/store_test.go
git commit -m "feat(initiatives): add Close/Archive lifecycle funnel

Strict forward-only active -> closed -> archived transition, enforced
via a conditional UPDATE ... WHERE state=<required> collapsing to a
shared ErrInvalidTransition sentinel on a zero-row update."
git push
```

---

## Task 4: `Store.ComputeProgress`

**Files:**
- Create: `internal/initiatives/progress.go`
- Create: `internal/initiatives/progress_test.go`

**Interfaces:**
- Consumes: `Store` from Task 2; `jobs.JobState*` constants conceptually (this package does not import `internal/jobs` — it queries the shared `jobs` table directly by string state values, matching those constants' literal values, the same way `internal/jobs` itself queries `job_targets` by literal state strings).
- Produces:
  ```go
  type Progress struct {
      Total, Requested, Running, Completed, Partial, Failed, Cancelled int
      PercentComplete float64
  }
  func (s *Store) ComputeProgress(ctx context.Context, initiativeID string) (Progress, error)
  ```
  Task 6 (`internal/api` GET handler) depends on this exact type and signature.

- [ ] **Step 1: Write the failing tests**

```go
package initiatives

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
)

func TestComputeProgress_CountsEveryJobState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		jobsStore := jobs.NewStore(pool)

		it, err := store.Create(ctx, "progress-mixed", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		mkJob := func(agentID string) jobs.Job {
			j, err := jobsStore.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{agentID})
			if err != nil {
				t.Fatalf("CreateBatch: %v", err)
			}
			if _, err := jobsStore.SetJobInitiative(ctx, j.ID, it.ID); err != nil {
				t.Fatalf("SetJobInitiative: %v", err)
			}
			return j
		}

		requested := mkJob("cp-a1") // stays requested (no targets marked)
		running := mkJob("cp-a2")
		if err := jobsStore.SetJobState(ctx, running.ID, jobs.JobStateRunning); err != nil {
			t.Fatalf("SetJobState(running): %v", err)
		}
		completed := mkJob("cp-a3")
		if err := jobsStore.SetJobState(ctx, completed.ID, jobs.JobStateCompleted); err != nil {
			t.Fatalf("SetJobState(completed): %v", err)
		}
		failed := mkJob("cp-a4")
		if err := jobsStore.SetJobState(ctx, failed.ID, jobs.JobStateFailed); err != nil {
			t.Fatalf("SetJobState(failed): %v", err)
		}
		_ = requested

		progress, err := store.ComputeProgress(ctx, it.ID)
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		want := Progress{Total: 4, Requested: 1, Running: 1, Completed: 1, Failed: 1, PercentComplete: 50}
		if progress != want {
			t.Errorf("progress = %+v, want %+v", progress, want)
		}
	})
}

func TestComputeProgress_NoSuchInitiative_ReturnsZeroValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		progress, err := store.ComputeProgress(context.Background(), "no-such-initiative-id")
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		if progress.Total != 0 || progress.PercentComplete != 0 {
			t.Errorf("progress = %+v, want all-zero for an initiative with no jobs", progress)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/initiatives/... -run TestComputeProgress -v`
Expected: FAIL — `ComputeProgress`/`Progress` undefined, and `jobs.Store.SetJobInitiative` undefined (that lands in Task 5 as a prerequisite the test file already references — see note below).

Note: this task's test file references `jobsStore.SetJobInitiative`, which does not exist until Task 5. Task ordering: **implement Task 5's `SetJobInitiative` method first if executing strictly in file-dependency order**, or write this test file now and leave it non-compiling until Task 5 lands, then return to run it. Either is fine since both tasks are committed independently; the plan lists `ComputeProgress` before `SetJobInitiative` because `ComputeProgress` is the more foundational piece for Task 6, but if the test in this step fails to *compile* (not just fails), skip straight to Task 5 Step 1-4, then return here.

- [ ] **Step 3: Write `progress.go`**

```go
package initiatives

import "context"

// Progress is a computed summary of one Initiative's member-Job state
// distribution -- never persisted, always derived fresh from jobs.
type Progress struct {
	Total           int
	Requested       int
	Running         int
	Completed       int
	Partial         int
	Failed          int
	Cancelled       int
	PercentComplete float64 // (Completed+Partial+Failed+Cancelled) / Total * 100; 0 if Total == 0
}

// ComputeProgress derives one Initiative's Progress via a grouped count
// over jobs -- at most 6 rows regardless of member-job count.
func (s *Store) ComputeProgress(ctx context.Context, initiativeID string) (Progress, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT state, COUNT(*) FROM jobs WHERE initiative_id=$1 GROUP BY state`, initiativeID)
	if err != nil {
		return Progress{}, err
	}
	defer rows.Close()

	var p Progress
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return Progress{}, err
		}
		switch state {
		case "requested":
			p.Requested = count
		case "running":
			p.Running = count
		case "completed":
			p.Completed = count
		case "partial":
			p.Partial = count
		case "failed":
			p.Failed = count
		case "cancelled":
			p.Cancelled = count
		}
		p.Total += count
	}
	if err := rows.Err(); err != nil {
		return Progress{}, err
	}
	if p.Total > 0 {
		terminal := p.Completed + p.Partial + p.Failed + p.Cancelled
		p.PercentComplete = float64(terminal) / float64(p.Total) * 100
	}
	return p, nil
}
```

The state string literals (`"requested"`, `"running"`, `"completed"`, `"partial"`, `"failed"`, `"cancelled"`) match `internal/jobs`' `JobStateRequested`/`JobStateRunning`/`JobStateCompleted`/`JobStatePartial`/`JobStateFailed`/`JobStateCancelled` constant values exactly (see `internal/jobs/types.go:14-20`) — this package deliberately does not import `internal/jobs` (per the spec's "zero cross-package imports" constraint), so the literals are hand-matched rather than referenced. The test file's own import of `internal/jobs` is fine (test-only, for `jobs.NewStore`/`jobs.JobState*` to drive fixtures) — only the non-test `store.go`/`progress.go` avoid the import.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/initiatives/... -v`
Expected: PASS for every test in the package (requires Task 5's `SetJobInitiative` to exist first per the Step 2 note — if it doesn't yet, do Task 5 Steps 1-4 now, then return and finish this step).

- [ ] **Step 5: Commit**

```bash
git add internal/initiatives/progress.go internal/initiatives/progress_test.go
git commit -m "feat(initiatives): add Store.ComputeProgress

Computed-on-read Job-state rollup for one Initiative, same
grouped-COUNT precedent as jobs.Store.ComputeProgress. PercentComplete
is terminal-based (completed+partial+failed+cancelled), not
success-based, matching JobProgress's existing semantics."
git push
```

---

## Task 5: `jobs.Store.SetJobInitiative` + `Job.InitiativeID`

**Files:**
- Modify: `internal/jobs/types.go` (add `InitiativeID` field to `Job`)
- Modify: `internal/jobs/store.go` (add `SetJobInitiative`, and add `initiative_id` to `Job`'s existing SELECT columns)
- Create: `internal/jobs/initiative_test.go`

**Interfaces:**
- Consumes: nothing new (works entirely within `internal/jobs` against the `initiative_id` column from Task 1).
- Produces:
  ```go
  func (s *Store) SetJobInitiative(ctx context.Context, jobID, initiativeID string) (Job, error)
  ```
  Task 4's test fixtures and Task 6 (`internal/api`) both depend on this exact signature. `Job.InitiativeID` (no JSON tag, matching every other field on `Job`) is read by Task 6's handlers.

- [ ] **Step 1: Write the failing test**

```go
package jobs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSetJobInitiative_AssignReassignClear(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"sji-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if job.InitiativeID != "" {
			t.Errorf("InitiativeID = %q on creation, want empty", job.InitiativeID)
		}

		assigned, err := store.SetJobInitiative(ctx, job.ID, "init-1")
		if err != nil {
			t.Fatalf("SetJobInitiative(assign): %v", err)
		}
		if assigned.InitiativeID != "init-1" {
			t.Errorf("InitiativeID = %q, want init-1", assigned.InitiativeID)
		}

		reassigned, err := store.SetJobInitiative(ctx, job.ID, "init-2")
		if err != nil {
			t.Fatalf("SetJobInitiative(reassign): %v", err)
		}
		if reassigned.InitiativeID != "init-2" {
			t.Errorf("InitiativeID = %q, want init-2", reassigned.InitiativeID)
		}

		cleared, err := store.SetJobInitiative(ctx, job.ID, "")
		if err != nil {
			t.Fatalf("SetJobInitiative(clear): %v", err)
		}
		if cleared.InitiativeID != "" {
			t.Errorf("InitiativeID = %q after clear, want empty", cleared.InitiativeID)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/jobs/... -run TestSetJobInitiative -v`
Expected: FAIL — `Job.InitiativeID` and `SetJobInitiative` undefined.

- [ ] **Step 3: Add `InitiativeID` to `Job` and wire it into `Get`/`CreateBatchWithConcurrency`**

In `internal/jobs/types.go`, add to the `Job` struct (after `ConcurrencyLimit`):

```go
	InitiativeID     string     // "" = not part of any initiative
```

In `internal/jobs/store.go`, update `Get` to select the new column:

```go
func (s *Store) Get(ctx context.Context, id string) (Job, error) {
	var j Job
	err := s.pool.QueryRow(ctx,
		`SELECT id, type, state, payload, created_by, created_at, started_at, completed_at, scheduled_at, concurrency_limit, initiative_id FROM jobs WHERE id=$1`, id,
	).Scan(&j.ID, &j.Type, &j.State, &j.Payload, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &j.ScheduledAt, &j.ConcurrencyLimit, &j.InitiativeID)
	return j, err
}
```

Add `SetJobInitiative` (place it near `SetTargetOwner` for locality):

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/jobs/... -run TestSetJobInitiative -v`
Expected: PASS.

- [ ] **Step 5: Run the full `internal/jobs` suite to confirm no regression**

Run (background):
```bash
go test ./internal/jobs/... -v > /tmp/jobs_suite.log 2>&1
```
Use Monitor / wait for completion, then read the actual log file in full (not a truncated tail) before proceeding. The `Get` signature change (new column in the SELECT) is the one change with blast radius across the whole package — confirm every existing test still passes.
Expected: PASS, zero `FAIL` lines.

- [ ] **Step 6: Commit**

```bash
git add internal/jobs/types.go internal/jobs/store.go internal/jobs/initiative_test.go
git commit -m "feat(jobs): add Job.InitiativeID and Store.SetJobInitiative

Pure plumbing for the Initiative layer -- internal/jobs knows nothing
about initiative lifecycle state; internal/api enforces membership
rules before calling this. Job.Get now also selects the new column."
git push
```

---

## Task 6: `internal/api/initiative_handlers.go` — all 6 endpoints

**Files:**
- Create: `internal/api/initiative_handlers.go`
- Create: `internal/api/initiative_handlers_test.go`
- Modify: `internal/api/handler.go` (or wherever `Handler` struct + `New`/`With*` constructors live — grep first, see Step 1) to add an `initiativesStore *initiatives.Store` field and a `WithInitiatives` chain method
- Modify: `internal/api/routes.go` (register the 6 routes)
- Modify: `internal/api/rbac_matrix_test.go` (add the 6 routes to `routeMatrix`)
- Modify: `main.go` (or wherever `WithJobsDispatcher` is currently chained onto `New(...)` at startup — grep first) to also chain `.WithInitiatives(initiatives.NewStore(pool))`

**Interfaces:**
- Consumes: `initiatives.Store` (Task 2-4), `jobs.Store.SetJobInitiative`/`Job.InitiativeID` (Task 5), `h.auditLog` (existing), `h.jobsStore` (existing field).
- Produces: the 6 HTTP endpoints exactly as specified in the spec's Components table.

- [ ] **Step 1: Find the exact `Handler` struct / constructor-chaining pattern**

Run: `grep -rn "func (h \*Handler) WithJobsDispatcher\|jobsStore \*jobs.Store" internal/api/*.go`

This locates the `Handler` struct definition (likely `internal/api/handler.go`) and confirms the exact field-declaration and `With*`-method style to copy. Also run `grep -rn "WithJobsDispatcher" main.go` to find the startup wiring call site.

- [ ] **Step 2: Add the `initiativesStore` field and `WithInitiatives` method**

In the `Handler` struct (wherever `jobsStore *jobs.Store` is declared), add a sibling field:

```go
	initiativesStore *initiatives.Store
```

Add the import `"github.com/audspect/bas/internal/initiatives"` to that file.

Add a chain method next to `WithJobsDispatcher` (in `internal/api/job_dispatch.go`, following that exact style):

```go
// WithInitiatives wires the Initiative layer's store into the handler.
func (h *Handler) WithInitiatives(store *initiatives.Store) *Handler {
	h.initiativesStore = store
	return h
}
```

- [ ] **Step 3: Wire it at startup**

In `main.go`, find the line chaining `.WithJobsDispatcher(...)` onto the `New(...)` call and add `.WithInitiatives(initiatives.NewStore(pool))` to the same chain. Add the `"github.com/audspect/bas/internal/initiatives"` import to `main.go`.

- [ ] **Step 4: Write the failing tests**

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/initiatives"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateInitiative_CreatesActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initiatives.NewStore(pool))

		body, _ := json.Marshal(map[string]string{"name": "Q3 Patch Compliance", "description": "quarterly push"})
		req := httptest.NewRequest(http.MethodPost, "/api/initiatives", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.CreateInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Initiative initiatives.Initiative `json:"initiative"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Initiative.State != initiatives.StateActive {
			t.Errorf("State = %q, want %q", resp.Initiative.State, initiatives.StateActive)
		}
	})
}

func TestAssignJobInitiative_RejectsNonActiveInitiative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('aji-a1', 'AJI-A1')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"aji-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		it, err := initStore.Create(context.Background(), "closed-init", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := initStore.Close(context.Background(), it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}

		body, _ := json.Marshal(map[string]string{"initiativeId": it.ID})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.SetJobInitiative(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body = %s, want 409", w.Code, w.Body.String())
		}
	})
}

func TestAssignJobInitiative_NonexistentInitiative_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('aji-a2', 'AJI-A2')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"aji-a2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		body, _ := json.Marshal(map[string]string{"initiativeId": "no-such-initiative"})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.SetJobInitiative(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want 404", w.Code, w.Body.String())
		}
	})
}

func TestAssignJobInitiative_DetachAlwaysAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('aji-a3', 'AJI-A3')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"aji-a3"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		it, err := initStore.Create(context.Background(), "detach-target", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := initStore.Close(context.Background(), it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := jobsStore.SetJobInitiative(context.Background(), job.ID, it.ID); err != nil {
			t.Fatalf("seed SetJobInitiative: %v", err)
		}

		body, _ := json.Marshal(map[string]string{"initiativeId": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.SetJobInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s, want 200 (detach always allowed even from a closed initiative)", w.Code, w.Body.String())
		}
	})
}

func TestCloseInitiative_WritesAuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "audit-close", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.CloseInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM audit_logs WHERE action='initiatives.closed' AND resource=$1`, it.ID,
		).Scan(&count); err != nil {
			t.Fatalf("query audit_logs: %v", err)
		}
		if count != 1 {
			t.Errorf("audit_logs rows for initiatives.closed = %d, want 1", count)
		}
	})
}

func TestArchiveInitiative_RejectsNonClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "archive-reject", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.ArchiveInitiative(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body = %s, want 409", w.Code, w.Body.String())
		}
	})
}

func TestGetInitiative_ReturnsProgressAndJobList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gi-a1', 'GI-A1')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "detail-view", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"gi-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if _, err := jobsStore.SetJobInitiative(context.Background(), job.ID, it.ID); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.GetInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Initiative initiatives.Initiative `json:"initiative"`
			Progress   initiatives.Progress   `json:"progress"`
			Jobs       []struct {
				ID string `json:"id"`
			} `json:"jobs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Progress.Total != 1 {
			t.Errorf("Progress.Total = %d, want 1", resp.Progress.Total)
		}
		if len(resp.Jobs) != 1 || resp.Jobs[0].ID != job.ID {
			t.Errorf("Jobs = %+v, want exactly the one seeded job", resp.Jobs)
		}
	})
}
```

Each test constructs its own handler inline, matching `job_target_handlers_test.go`'s established per-test pattern — no shared helper needed.

- [ ] **Step 5: Run tests to verify they fail**

Run: `go test ./internal/api/... -run 'TestCreateInitiative|TestAssignJobInitiative|TestCloseInitiative|TestArchiveInitiative|TestGetInitiative' -v`
Expected: FAIL — `CreateInitiative`/`SetJobInitiative`/`CloseInitiative`/`ArchiveInitiative`/`GetInitiative` undefined on `*Handler`.

- [ ] **Step 6: Write `internal/api/initiative_handlers.go`**

```go
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/initiatives"
)

// CreateInitiative creates a new Initiative in the active state.
// POST /api/initiatives  body: {name, description}
func (h *Handler) CreateInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	it, err := h.initiativesStore.Create(r.Context(), req.Name, req.Description, actorID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"initiative": it})
}

// ListInitiatives lists every Initiative, optionally filtered by state.
// GET /api/initiatives?state=active|closed|archived
func (h *Handler) ListInitiatives(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	state := r.URL.Query().Get("state")
	list, err := h.initiativesStore.List(r.Context(), state)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"initiatives": list})
}

// GetInitiative returns one Initiative plus its derived Progress and a
// lightweight list of member jobs (no target-level nesting).
// GET /api/initiatives/{initiativeId}
func (h *Handler) GetInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil || h.jobsStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "initiativeId")
	it, err := h.initiativesStore.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "initiative not found", http.StatusNotFound)
		return
	}
	progress, err := h.initiativesStore.ComputeProgress(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT id, type, state, created_at, completed_at FROM jobs WHERE initiative_id=$1 ORDER BY created_at`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type jobSummary struct {
		ID          string     `json:"id"`
		Type        string     `json:"type"`
		State       string     `json:"state"`
		CreatedAt   time.Time  `json:"createdAt"`
		CompletedAt *time.Time `json:"completedAt,omitempty"`
	}
	var jobSummaries []jobSummary
	for rows.Next() {
		var js jobSummary
		if err := rows.Scan(&js.ID, &js.Type, &js.State, &js.CreatedAt, &js.CompletedAt); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jobSummaries = append(jobSummaries, js)
	}
	respond(w, map[string]any{"initiative": it, "progress": progress, "jobs": jobSummaries})
}

// CloseInitiative moves an Initiative from active to closed.
// POST /api/initiatives/{initiativeId}/close
func (h *Handler) CloseInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "initiativeId")
	it, err := h.initiativesStore.Close(r.Context(), id)
	if errors.Is(err, initiatives.ErrInvalidTransition) {
		jsonError(w, "initiative is not active", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "initiatives.closed", id, map[string]any{}, "ok")
	respond(w, map[string]any{"initiative": it})
}

// ArchiveInitiative moves an Initiative from closed to archived.
// POST /api/initiatives/{initiativeId}/archive
func (h *Handler) ArchiveInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "initiativeId")
	it, err := h.initiativesStore.Archive(r.Context(), id)
	if errors.Is(err, initiatives.ErrInvalidTransition) {
		jsonError(w, "initiative is not closed", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "initiatives.archived", id, map[string]any{}, "ok")
	respond(w, map[string]any{"initiative": it})
}

// SetJobInitiative assigns, reassigns, or clears (initiativeId: "") a
// job's initiative membership. Assigning to a non-active initiative is
// rejected; detaching is always allowed regardless of the initiative's
// current state.
// PATCH /api/jobs/{jobId}/initiative  body: {initiativeId}
func (h *Handler) SetJobInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil || h.jobsStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	jobID := chi.URLParam(r, "jobId")
	var req struct {
		InitiativeID string `json:"initiativeId"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}

	previous, err := h.jobsStore.Get(r.Context(), jobID)
	if err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}

	if req.InitiativeID != "" {
		target, err := h.initiativesStore.Get(r.Context(), req.InitiativeID)
		if err != nil {
			jsonError(w, "initiative not found", http.StatusNotFound)
			return
		}
		if target.State != initiatives.StateActive {
			jsonError(w, "initiative is "+target.State+", not active", http.StatusConflict)
			return
		}
	}

	job, err := h.jobsStore.SetJobInitiative(r.Context(), jobID, req.InitiativeID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.InitiativeID == "" {
		h.auditLog(r, "initiatives.job_detached", previous.InitiativeID, map[string]any{"jobId": jobID}, "ok")
	} else {
		h.auditLog(r, "initiatives.job_assigned", req.InitiativeID,
			map[string]any{"jobId": jobID, "previousInitiativeId": previous.InitiativeID}, "ok")
	}
	respond(w, map[string]any{"job": job})
}
```

- [ ] **Step 7: Register the routes**

In `internal/api/routes.go`, find the block of `r.With(auth.RequirePermission(auth.CanExecuteRemediation))...` lines for jobs (around the existing `/api/jobs/*` lines) and add:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/initiatives", h.CreateInitiative)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/initiatives", h.ListInitiatives)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/initiatives/{initiativeId}", h.GetInitiative)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/initiatives/{initiativeId}/close", h.CloseInitiative)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/initiatives/{initiativeId}/archive", h.ArchiveInitiative)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Patch("/api/jobs/{jobId}/initiative", h.SetJobInitiative)
```

- [ ] **Step 8: Add the 6 routes to `rbac_matrix_test.go`**

In `internal/api/rbac_matrix_test.go`, in the `routeMatrix` slice, add (near the existing `/api/job-targets` rows):

```go
	{http.MethodPost, "/api/initiatives", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/initiatives", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/initiatives/{initiativeId}", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/initiatives/{initiativeId}/close", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/initiatives/{initiativeId}/archive", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPatch, "/api/jobs/{jobId}/initiative", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 9: Run the new tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestCreateInitiative|TestAssignJobInitiative|TestCloseInitiative|TestArchiveInitiative|TestGetInitiative' -v`
Expected: PASS for all.

- [ ] **Step 10: Run `TestRBACMatrix_NoDrift` specifically**

Run: `go test ./internal/api/... -run TestRBACMatrix -v`
Expected: PASS — confirms the 6 new routes registered in `routes.go` (Step 7) exactly match the 6 rows added to `routeMatrix` (Step 8), including method and path template.

- [ ] **Step 11: Run the full `internal/api` suite (background + Monitor, read the real log)**

Run (background):
```bash
go test ./internal/api/... -timeout 20m > /tmp/api_suite_initiatives.log 2>&1
```
Wait for completion notification, then read `/tmp/api_suite_initiatives.log` in full. If a failure appears that looks like Docker/testcontainer contention (this initiative has repeatedly hit this — `unexpected EOF` on the shared Postgres container mid-run), re-run just that failing test name in isolation before treating it as a regression.
Expected: PASS, zero real `FAIL` lines.

- [ ] **Step 12: Commit**

```bash
git add internal/api/initiative_handlers.go internal/api/initiative_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/job_dispatch.go main.go
git commit -m "feat(api): add Initiative layer REST endpoints

6 endpoints (create/list/get/close/archive an Initiative; assign/
reassign/detach a Job's initiative membership), all gated on
CanExecuteRemediation -- same tier as creating the underlying jobs, no
new permission. Every membership change and lifecycle transition
writes an audit_logs row via the existing auditLog helper."
git push
```

---

## Task 7: Confirm no `wwwroot` changes (explicit no-op step)

**Files:** none.

**Interfaces:** none.

- [ ] **Step 1: Confirm scope boundary**

Run: `git status --porcelain wwwroot/`
Expected: empty output — this plan makes zero changes anywhere under `wwwroot/`, per the spec's explicit scope decision (backend/API only, UI is a separate follow-on sub-project). This step exists so that boundary is verified, not silently assumed.

- [ ] **Step 2: Run the full repository test suite one final time**

Run (background):
```bash
go build ./... > /tmp/build_final.log 2>&1 && go test ./... -timeout 20m > /tmp/full_suite_final.log 2>&1
```
Wait for completion, read both log files in full.
Expected: build succeeds; test suite passes (allowing for the already-documented Docker/testcontainer contention class of failure, which must be individually re-confirmed via isolated re-run before being dismissed).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-22-initiative-layer.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

This session has repeatedly and consistently preferred **Inline Execution** for this initiative — noting that as the default unless you want to switch.
