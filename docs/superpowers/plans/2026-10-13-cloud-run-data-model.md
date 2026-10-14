# Cloud Run Data Model & Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give cloud scenario runs their own persistence layer — a `cloud_runs` table with no endpoint-agent assumptions, plus the Go type and store functions to create, update, and read rows in it.

**Architecture:** One new Postgres table (`cloud_runs`), one new Go package (`internal/cloudrun`) holding the lifecycle type, and one new store file (`internal/db/cloudrun_store.go`) with four CRUD functions, wired into the existing `EnsureXSchema`-per-feature migration convention. No existing table is altered; two existing files (`cmd/server/main.go`, `internal/testutil/testdb.go`) each get one line added, following the exact pattern every other recent `EnsureXSchema` function already uses.

**Tech Stack:** Go, `github.com/jackc/pgx/v5` / `pgxpool`, Postgres 16, `testcontainers-go` for the test harness (requires a running Docker daemon — see Review Focus).

**Spec:** `docs/superpowers/specs/2026-10-13-cloud-run-data-model-design.md`

## Global Constraints

- TDD throughout: every test is written, watched fail (for the reason the plan says), then made to pass. No production code before its failing test.
- Narrow verification after each step (the single test file / package); one full `go test ./internal/db/... ./internal/cloudrun/...` gate at the end of the last task.
- Minimal changes only: exactly three new files (`internal/cloudrun/types.go`, `internal/db/cloudrun_store.go`, `internal/db/cloudrun_store_test.go`), plus one added line each in `cmd/server/main.go` and `internal/testutil/testdb.go` to wire the new schema function into the existing per-feature `EnsureXSchema` chain — nothing else is touched, no existing table is altered.
- No subagents are needed for this plan (three small, sequential files); if any become necessary later, Sonnet only, never Opus.
- Git push immediately after every commit. Before each push attempt, run `git fetch && git log --oneline main..origin/main` — this repo has had concurrent pushes from another active session today (both resolved cleanly via `git pull`, no conflicts touching `cloudgraph`/`cloudrun` files). If `git pull` reports anything, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass before pushing, same as was done earlier this session.

## Review Focus

- **Docker must be running for these tests to execute at all.** `internal/testutil/testdb.go`'s `newTestDB` uses `testcontainers-go` to start a real `postgres:16-alpine` container — there is no build tag or skip-if-unavailable guard. If Docker Desktop isn't running, every test in this plan fails at container startup (not a clean skip) with a clear `testutil: start postgres container` error. Start Docker Desktop before running any test step below.
- Both `cloud_runs` CHECK constraints (`status`, `provider`) must be proven to reject *and* accept correctly, independently of each other — a test that only exercises one constraint leaves the other's exact accepted-value set unverified.
- The `result` jsonb column must prove it round-trips a genuinely structured value (nested objects/arrays), not just `{}` or a bare string — a flat/empty fixture would pass even if `jsonb`↔`json.RawMessage` encoding silently reformatted or truncated structure.
- Every real cloud run starts with `result = NULL` (nothing to report yet) — this path must be proven not to error on `Get`, not just the non-nil case, since sub-project #2's harness will insert exactly this shape on every run it creates.
- `GetCloudRun` on a missing ID must be proven to satisfy `errors.Is(err, pgx.ErrNoRows)`, not merely "returns some error" — a caller matching on the wrong error type would silently fail to distinguish "not found" from "query failed."

---

## File Structure

- **Create** `orchestrator/internal/cloudrun/types.go` — the `Status` type, its 5 constants, and the `CloudRun` struct. No behavior, no imports beyond `encoding/json` and `time`.
- **Create** `orchestrator/internal/db/cloudrun_store.go` — `EnsureCloudRunSchema`, `InsertCloudRun`, `GetCloudRun`, `UpdateCloudRunStatus`, `ListCloudRuns`, and a private `scanCloudRun` helper shared by `GetCloudRun`/`ListCloudRuns`.
- **Create** `orchestrator/internal/db/cloudrun_store_test.go` — package `db_test`, using the `sharedDB` package variable and `TestMain` already declared in `internal/db/tenant_test.go` (do not redeclare either).
- **Modify** `orchestrator/cmd/server/main.go:285` (immediately after the existing `EnsureThreatIdentitySchema` call, before the `"[+] Schema verified"` log line) — add the `EnsureCloudRunSchema` bootstrap call, exact same style as its neighbors.
- **Modify** `orchestrator/internal/testutil/testdb.go` (in `newTestDB`, immediately after the existing `EnsureThreatIdentitySchema` call) — add the matching call so every test using the shared test-DB harness gets the `cloud_runs` table for free, exact same style as its neighbors.

## Task 1: Schema migration (`EnsureCloudRunSchema`)

**Files:**
- Create: `orchestrator/internal/db/cloudrun_store.go` (schema function only — CRUD functions come in later tasks)
- Create: `orchestrator/internal/db/cloudrun_store_test.go` (schema tests only — more tests appended in later tasks)
- Modify: `orchestrator/cmd/server/main.go:285`
- Modify: `orchestrator/internal/testutil/testdb.go:125` (after the `EnsureThreatIdentitySchema` block, before the closing of `newTestDB`'s error-checking chain)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `db.EnsureCloudRunSchema(ctx context.Context, pool *pgxpool.Pool) error` — called by Tasks 2-4's tests indirectly via the `testutil`/`main.go` wiring added in this task (later tasks' tests do **not** call it directly; the shared test-DB container already has the table).

- [ ] **Step 1: Write the failing schema tests**

Create `orchestrator/internal/db/cloudrun_store_test.go`:

```go
package db_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestCloudRunSchema_Idempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsureCloudRunSchema(ctx, pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='cloud_runs'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("cloud_runs table missing (n=%d err=%v)", n, err)
		}
	})
}

func TestCloudRunSchema_StatusCheckConstraint(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		cases := []struct {
			status string
			legal  bool
		}{
			{"pending", true},
			{"running", true},
			{"completed", true},
			{"failed", true},
			{"partial", true},
			{"bogus", false},
			{"", false},
		}
		for i, c := range cases {
			id := fmt.Sprintf("status-case-%d", i)
			_, err := pool.Exec(ctx, `INSERT INTO cloud_runs (id, scenario_id, provider, status) VALUES ($1, 'x', 'aws', $2)`, id, c.status)
			if got := err == nil; got != c.legal {
				t.Errorf("status=%q: accepted=%v want %v (err=%v)", c.status, got, c.legal, err)
			}
		}
	})
}

func TestCloudRunSchema_ProviderCheckConstraint(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		cases := []struct {
			provider string
			legal    bool
		}{
			{"aws", true},
			{"azure", true},
			{"gcp", true},
			{"bogus", false},
			{"", false},
		}
		for i, c := range cases {
			id := fmt.Sprintf("provider-case-%d", i)
			_, err := pool.Exec(ctx, `INSERT INTO cloud_runs (id, scenario_id, provider) VALUES ($1, 'x', $2)`, id, c.provider)
			if got := err == nil; got != c.legal {
				t.Errorf("provider=%q: accepted=%v want %v (err=%v)", c.provider, got, c.legal, err)
			}
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Ensure Docker Desktop is running first (see Review Focus). Run: `go test ./internal/db/... -run TestCloudRunSchema -v`
Expected: compile failure — `undefined: db.EnsureCloudRunSchema` (the function doesn't exist yet). This is the correct RED: it fails because the feature is missing, not because of a typo.

- [ ] **Step 3: Write the minimal schema function**

Create `orchestrator/internal/db/cloudrun_store.go`:

```go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureCloudRunSchema creates the cloud_runs table -- the execution-tracking
// record for one cloud scenario run against one account scope. See
// docs/superpowers/specs/2026-10-13-cloud-run-data-model-design.md. Unlike
// scenario_runs, there is deliberately no agent_id / FK to agents: a cloud
// scenario has no endpoint agent to dispatch to.
func EnsureCloudRunSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS cloud_runs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			scenario_id   text        NOT NULL,
			provider      text        NOT NULL,
			account_id    text        NOT NULL DEFAULT '',
			tenant_id     text        NOT NULL DEFAULT '',
			region        text        NOT NULL DEFAULT '',
			status        text        NOT NULL DEFAULT 'pending',
			result        jsonb,
			error         text,
			initiated_by  text,
			started_at    timestamptz NOT NULL DEFAULT NOW(),
			completed_at  timestamptz,
			CONSTRAINT cloud_runs_status_check   CHECK (status IN ('pending','running','completed','failed','partial')),
			CONSTRAINT cloud_runs_provider_check CHECK (provider IN ('aws','azure','gcp'))
		)`)
	if err != nil {
		return fmt.Errorf("cloud_runs: ensure schema: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/db/... -run TestCloudRunSchema -v`
Expected: `PASS` on all three tests (`TestCloudRunSchema_Idempotent`, `TestCloudRunSchema_StatusCheckConstraint`, `TestCloudRunSchema_ProviderCheckConstraint`).

- [ ] **Step 5: Wire the schema into server startup**

In `orchestrator/cmd/server/main.go`, immediately after the existing block:

```go
	if err := db.EnsureThreatIdentitySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] threat identity schema: %v", err)
	}
```

add:

```go
	if err := db.EnsureCloudRunSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] cloud run schema: %v", err)
	}
```

- [ ] **Step 6: Wire the schema into the shared test-DB harness**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block:

```go
	if err := db.EnsureThreatIdentitySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureThreatIdentitySchema: %w", err)
	}
```

add:

```go
	if err := db.EnsureCloudRunSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureCloudRunSchema: %w", err)
	}
```

- [ ] **Step 7: Run the full db package build + schema tests to verify nothing broke**

Run: `go build ./... && go test ./internal/db/... -run TestCloudRunSchema -v`
Expected: build succeeds, all three schema tests still `PASS` (confirms `main.go`'s edit compiles and `testdb.go`'s edit didn't break container setup).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/db/cloudrun_store.go orchestrator/internal/db/cloudrun_store_test.go orchestrator/cmd/server/main.go orchestrator/internal/testutil/testdb.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add cloud_runs table schema

First piece of the cloud run data model (sub-project #1 of wiring
cloudgraph into live dispatch). No agent_id/FK to agents -- a cloud
scenario has no endpoint agent to dispatch to, unlike scenario_runs.
Wired into the existing per-feature EnsureXSchema chain in both
cmd/server/main.go and the shared test-DB harness.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

## Task 2: `cloudrun.CloudRun` type + Insert/Get

**Files:**
- Create: `orchestrator/internal/cloudrun/types.go`
- Modify: `orchestrator/internal/db/cloudrun_store.go` (append `InsertCloudRun`, `GetCloudRun`, `scanCloudRun`)
- Modify: `orchestrator/internal/db/cloudrun_store_test.go` (append tests)

**Interfaces:**
- Consumes: `db.EnsureCloudRunSchema` (Task 1) — already wired into the shared test harness, not called directly by this task's tests.
- Produces: `cloudrun.Status` (type `string`) with constants `StatusPending`, `StatusRunning`, `StatusCompleted`, `StatusFailed`, `StatusPartial`; `cloudrun.CloudRun` struct with fields `ID, ScenarioID, Provider, AccountID, TenantID, Region string`, `Status cloudrun.Status`, `Result json.RawMessage`, `Error, InitiatedBy string`, `StartedAt time.Time`, `CompletedAt *time.Time`; `db.InsertCloudRun(ctx, pool, run *cloudrun.CloudRun) error`; `db.GetCloudRun(ctx, pool, id string) (*cloudrun.CloudRun, error)`. Task 3 and Task 4 both consume all of the above.

- [ ] **Step 1: Write the failing round-trip tests**

Append to `orchestrator/internal/db/cloudrun_store_test.go` (add these imports to the existing `import` block: `"encoding/json"`, `"errors"`, `"time"`, `"github.com/jackc/pgx/v5"`, `"github.com/audspect/bas/internal/cloudrun"`):

```go
func TestInsertAndGetCloudRun_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		result := json.RawMessage(`{"hops":[{"edge":"role-a","state":"observed"},{"edge":"role-b","state":"policy_supported"}],"overallState":"policy_supported"}`)
		started := time.Now().UTC().Truncate(time.Microsecond)
		run := &cloudrun.CloudRun{
			ID:          "run-1",
			ScenarioID:  "cloud-ransomware-s3",
			Provider:    "aws",
			AccountID:   "111122223333",
			TenantID:    "",
			Region:      "us-east-1",
			Status:      cloudrun.StatusRunning,
			Result:      result,
			Error:       "",
			InitiatedBy: "tausif",
			StartedAt:   started,
			CompletedAt: nil,
		}
		if err := db.InsertCloudRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetCloudRun(ctx, pool, "run-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ID != run.ID || got.ScenarioID != run.ScenarioID || got.Provider != run.Provider ||
			got.AccountID != run.AccountID || got.Region != run.Region || got.Status != run.Status ||
			got.InitiatedBy != run.InitiatedBy {
			t.Fatalf("round-trip field mismatch: got %+v, want %+v", got, run)
		}
		if string(got.Result) != string(result) {
			t.Fatalf("result mismatch: got %s want %s", got.Result, result)
		}
		if !got.StartedAt.Equal(started) {
			t.Fatalf("startedAt mismatch: got %v want %v", got.StartedAt, started)
		}
		if got.CompletedAt != nil {
			t.Fatalf("completedAt: got %v want nil", got.CompletedAt)
		}
	})
}

func TestInsertCloudRun_NilResultRoundTrips(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &cloudrun.CloudRun{
			ID:         "run-nil-result",
			ScenarioID: "cloud-plan-search",
			Provider:   "azure",
			Status:     cloudrun.StatusPending,
			StartedAt:  time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := db.InsertCloudRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetCloudRun(ctx, pool, "run-nil-result")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Result != nil {
			t.Fatalf("result: got %s want nil", got.Result)
		}
	})
}

func TestGetCloudRun_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := db.GetCloudRun(ctx, pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("want pgx.ErrNoRows, got %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/db/... -run 'TestInsertAndGetCloudRun_RoundTrip|TestInsertCloudRun_NilResultRoundTrips|TestGetCloudRun_NotFound' -v`
Expected: compile failure — `undefined: cloudrun.CloudRun` (the package doesn't exist yet).

- [ ] **Step 3: Create the `cloudrun` package**

Create `orchestrator/internal/cloudrun/types.go`:

```go
// Package cloudrun holds the lifecycle record for one cloud scenario run.
// Kept separate from cloudgraph since lifecycle/persistence tracking is a
// different concern from cloudgraph's pure graph/evaluation scope -- mirrors
// how rwevidence is its own domain package, distinct from adprimitive/adchain.
package cloudrun

import (
	"encoding/json"
	"time"
)

// Status is a cloud_runs.status value.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusPartial   Status = "partial"
)

// CloudRun is one execution of one cloud scenario against one account
// scope. Result is deliberately opaque -- this package defines the
// lifecycle a run goes through, not what a given scenario's execution
// harness (a later sub-project) actually produces as evidence.
type CloudRun struct {
	ID          string
	ScenarioID  string
	Provider    string
	AccountID   string
	TenantID    string
	Region      string
	Status      Status
	Result      json.RawMessage
	Error       string
	InitiatedBy string
	StartedAt   time.Time
	CompletedAt *time.Time
}
```

- [ ] **Step 4: Run the tests again to verify the next failure**

Run: `go test ./internal/db/... -run 'TestInsertAndGetCloudRun_RoundTrip|TestInsertCloudRun_NilResultRoundTrips|TestGetCloudRun_NotFound' -v`
Expected: compile failure — `undefined: db.InsertCloudRun` (the type now exists; the store functions don't yet).

- [ ] **Step 5: Implement `InsertCloudRun` and `GetCloudRun`**

Append to `orchestrator/internal/db/cloudrun_store.go` (add `"github.com/audspect/bas/internal/cloudrun"` and `"github.com/jackc/pgx/v5"` to the existing import block):

```go
// InsertCloudRun writes a new cloud_runs row. The caller supplies run.ID
// already generated (matching scenario_runs' existing convention of
// generating the run ID in Go before insert) and run.Status explicitly --
// the column's DEFAULT 'pending' is a fallback for direct SQL, not relied
// on here, since the lifecycle spec leaves "created pending or running" to
// the caller.
func InsertCloudRun(ctx context.Context, pool *pgxpool.Pool, run *cloudrun.CloudRun) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO cloud_runs (id, scenario_id, provider, account_id, tenant_id, region, status, result, error, initiated_by, started_at, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		run.ID, run.ScenarioID, run.Provider, run.AccountID, run.TenantID, run.Region,
		string(run.Status), run.Result, run.Error, run.InitiatedBy, run.StartedAt, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("cloud_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

// scanCloudRun scans one cloud_runs row, shared by GetCloudRun and
// ListCloudRuns so the column list exists in exactly one place.
func scanCloudRun(row pgx.Row) (*cloudrun.CloudRun, error) {
	run := &cloudrun.CloudRun{}
	var status string
	if err := row.Scan(&run.ID, &run.ScenarioID, &run.Provider, &run.AccountID, &run.TenantID, &run.Region,
		&status, &run.Result, &run.Error, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	run.Status = cloudrun.Status(status)
	return run, nil
}

// GetCloudRun returns one cloud_runs row by id. A missing id returns an
// error satisfying errors.Is(err, pgx.ErrNoRows) -- the standard pgx idiom,
// not a custom "not found" sentinel.
func GetCloudRun(ctx context.Context, pool *pgxpool.Pool, id string) (*cloudrun.CloudRun, error) {
	row := pool.QueryRow(ctx, `
		SELECT id, scenario_id, provider, account_id, tenant_id, region, status, result, error, initiated_by, started_at, completed_at
		FROM cloud_runs WHERE id = $1`, id)
	run, err := scanCloudRun(row)
	if err != nil {
		return nil, fmt.Errorf("cloud_runs: get %s: %w", id, err)
	}
	return run, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/db/... -run 'TestInsertAndGetCloudRun_RoundTrip|TestInsertCloudRun_NilResultRoundTrips|TestGetCloudRun_NotFound' -v`
Expected: `PASS` on all three.

- [ ] **Step 7: Run the whole package to verify nothing broke**

Run: `go test ./internal/db/... ./internal/cloudrun/...`
Expected: all tests pass, including Task 1's schema tests.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/cloudrun/types.go orchestrator/internal/db/cloudrun_store.go orchestrator/internal/db/cloudrun_store_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add CloudRun type and Insert/Get store functions

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

## Task 3: `UpdateCloudRunStatus`

**Files:**
- Modify: `orchestrator/internal/db/cloudrun_store.go` (append `UpdateCloudRunStatus`)
- Modify: `orchestrator/internal/db/cloudrun_store_test.go` (append tests)

**Interfaces:**
- Consumes: `cloudrun.CloudRun`, `cloudrun.Status` + constants, `db.InsertCloudRun`, `db.GetCloudRun` (Task 2).
- Produces: `db.UpdateCloudRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status cloudrun.Status, result json.RawMessage, errMsg string) error`. Task 4 does not depend on this, but shares the test file.

- [ ] **Step 1: Write the failing status-transition tests**

Append to `orchestrator/internal/db/cloudrun_store_test.go`:

```go
func TestUpdateCloudRunStatus_TerminalStatusesSetCompletedAt(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		cases := []cloudrun.Status{cloudrun.StatusCompleted, cloudrun.StatusFailed, cloudrun.StatusPartial}
		for _, status := range cases {
			id := "terminal-" + string(status)
			run := &cloudrun.CloudRun{ID: id, ScenarioID: "x", Provider: "gcp", Status: cloudrun.StatusRunning, StartedAt: time.Now().UTC()}
			if err := db.InsertCloudRun(ctx, pool, run); err != nil {
				t.Fatalf("insert %s: %v", id, err)
			}
			if err := db.UpdateCloudRunStatus(ctx, pool, id, status, json.RawMessage(`{"ok":true}`), ""); err != nil {
				t.Fatalf("update %s: %v", id, err)
			}
			got, err := db.GetCloudRun(ctx, pool, id)
			if err != nil {
				t.Fatalf("get %s: %v", id, err)
			}
			if got.Status != status {
				t.Errorf("status: got %s want %s", got.Status, status)
			}
			if got.CompletedAt == nil {
				t.Errorf("status=%s: completedAt is nil, want set", status)
			}
		}
	})
}

func TestUpdateCloudRunStatus_RunningLeavesCompletedAtNull(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &cloudrun.CloudRun{ID: "still-running", ScenarioID: "x", Provider: "aws", Status: cloudrun.StatusPending, StartedAt: time.Now().UTC()}
		if err := db.InsertCloudRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := db.UpdateCloudRunStatus(ctx, pool, "still-running", cloudrun.StatusRunning, nil, ""); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := db.GetCloudRun(ctx, pool, "still-running")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != cloudrun.StatusRunning {
			t.Errorf("status: got %s want running", got.Status)
		}
		if got.CompletedAt != nil {
			t.Errorf("completedAt: got %v want nil", got.CompletedAt)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/db/... -run TestUpdateCloudRunStatus -v`
Expected: compile failure — `undefined: db.UpdateCloudRunStatus`.

- [ ] **Step 3: Implement `UpdateCloudRunStatus`**

Append to `orchestrator/internal/db/cloudrun_store.go`:

```go
// UpdateCloudRunStatus transitions a cloud_runs row's status. completed_at
// is set to NOW() only for the three terminal statuses (completed/failed/
// partial); a transition to running (or pending) leaves it null. result/
// errMsg are both optional -- a transition to running typically has
// neither.
func UpdateCloudRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status cloudrun.Status, result json.RawMessage, errMsg string) error {
	terminal := status == cloudrun.StatusCompleted || status == cloudrun.StatusFailed || status == cloudrun.StatusPartial
	var err error
	if terminal {
		_, err = pool.Exec(ctx, `UPDATE cloud_runs SET status = $1, result = $2, error = $3, completed_at = NOW() WHERE id = $4`,
			string(status), result, errMsg, id)
	} else {
		_, err = pool.Exec(ctx, `UPDATE cloud_runs SET status = $1, result = $2, error = $3 WHERE id = $4`,
			string(status), result, errMsg, id)
	}
	if err != nil {
		return fmt.Errorf("cloud_runs: update status for %s: %w", id, err)
	}
	return nil
}
```

Add `"encoding/json"` to `cloudrun_store.go`'s import block (needed for the `json.RawMessage` parameter type).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/db/... -run TestUpdateCloudRunStatus -v`
Expected: `PASS` on both tests.

- [ ] **Step 5: Run the whole package to verify nothing broke**

Run: `go test ./internal/db/... ./internal/cloudrun/...`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/cloudrun_store.go orchestrator/internal/db/cloudrun_store_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add UpdateCloudRunStatus

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

## Task 4: `ListCloudRuns`

**Files:**
- Modify: `orchestrator/internal/db/cloudrun_store.go` (append `ListCloudRuns`)
- Modify: `orchestrator/internal/db/cloudrun_store_test.go` (append test)

**Interfaces:**
- Consumes: `cloudrun.CloudRun`, `db.InsertCloudRun` (Task 2), `scanCloudRun` (Task 2, package-private).
- Produces: `db.ListCloudRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*cloudrun.CloudRun, error)`. This is the last task — no later task consumes this.

- [ ] **Step 1: Write the failing ordering/limit test**

Append to `orchestrator/internal/db/cloudrun_store_test.go`:

```go
func TestListCloudRuns_OrderingAndLimit(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := time.Now().UTC().Add(-time.Hour)
		ids := []string{"list-1", "list-2", "list-3", "list-4", "list-5"}
		for i, id := range ids {
			run := &cloudrun.CloudRun{
				ID: id, ScenarioID: "x", Provider: "aws", Status: cloudrun.StatusCompleted,
				StartedAt: base.Add(time.Duration(i) * time.Minute),
			}
			if err := db.InsertCloudRun(ctx, pool, run); err != nil {
				t.Fatalf("insert %s: %v", id, err)
			}
		}
		got, err := db.ListCloudRuns(ctx, pool, 3)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("len: got %d want 3", len(got))
		}
		want := []string{"list-5", "list-4", "list-3"}
		for i, w := range want {
			if got[i].ID != w {
				t.Errorf("position %d: got %s want %s", i, got[i].ID, w)
			}
		}
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/db/... -run TestListCloudRuns_OrderingAndLimit -v`
Expected: compile failure — `undefined: db.ListCloudRuns`.

- [ ] **Step 3: Implement `ListCloudRuns`**

Append to `orchestrator/internal/db/cloudrun_store.go`:

```go
// ListCloudRuns returns up to limit cloud_runs rows, newest started_at
// first. No filter parameters -- speculative until a real consumer (a
// later sub-project's API endpoint) reveals what filtering is actually
// needed.
func ListCloudRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*cloudrun.CloudRun, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, scenario_id, provider, account_id, tenant_id, region, status, result, error, initiated_by, started_at, completed_at
		FROM cloud_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("cloud_runs: list: %w", err)
	}
	defer rows.Close()
	var runs []*cloudrun.CloudRun
	for rows.Next() {
		run, err := scanCloudRun(rows)
		if err != nil {
			return nil, fmt.Errorf("cloud_runs: list scan: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cloud_runs: list rows: %w", err)
	}
	return runs, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/db/... -run TestListCloudRuns_OrderingAndLimit -v`
Expected: `PASS`.

- [ ] **Step 5: Run the full gate**

Run: `go build ./... && go test ./internal/db/... ./internal/cloudrun/...`
Expected: build succeeds; every test in both packages passes (schema idempotency + both CHECK constraints, insert/get round-trip, nil-result round-trip, not-found, both status-transition cases, ordering+limit).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/cloudrun_store.go orchestrator/internal/db/cloudrun_store_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add ListCloudRuns

Completes sub-project #1 (cloud run data model & lifecycle) of wiring
cloudgraph's standalone capabilities into live dispatch. Result shape,
campaign grouping, and any API/UI remain explicitly deferred to later
sub-projects -- see docs/superpowers/specs/2026-10-13-cloud-run-data-model-design.md.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.
