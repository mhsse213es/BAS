# Job-Target Ownership (Phase 8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `JobTarget` (an individual agent's slice of a Fleet Job Engine job) be assigned a specific owner, notify that owner on assignment via Phase 7's existing notification pipeline, and let an owner list everything currently assigned to them across every job.

**Architecture:** Purely additive `owner_id`/`assigned_at` columns on the existing `job_targets` table (no new table). Two new `jobs.Store` methods (`SetTargetOwner`, `ListTargetsByOwner`) alongside the existing target-mutation methods. Two new `internal/api` handlers wired directly to `internal/notifications` (no `Dispatcher`/`NotifyFn` involvement — assignment is an operator action, not a `Tick()`-driven state transition, same shape as `CancelJob`).

**Tech Stack:** Go, PostgreSQL (pgx/v5), chi router.

## Global Constraints

- No branches/PRs — commit directly to `main`, matching this initiative's established convention.
- `git push` after every commit.
- `owner_id` carries no foreign-key constraint to `users.id` — matches `requested_by`/`approved_by`/`created_by`'s existing convention everywhere else in this codebase (bare string trusting the auth layer).
- Only `JobTarget`s are owned, never whole `Job`s. No auto-assignment logic (manual only). No ownership-history table (the existing `audit_logs` insert via `h.auditLog` already records every assign/clear action).
- RBAC: both new endpoints use `auth.CanExecuteRemediation` (Analyst+Admin) — no new permission.

---

## File Structure

- **Modify** `orchestrator/internal/db/postgres.go` — add `owner_id`/`assigned_at` columns + index to `job_targets`.
- **Modify** `orchestrator/internal/jobs/types.go` — add `OwnerID`/`AssignedAt` fields to `JobTarget`.
- **Modify** `orchestrator/internal/jobs/store.go` — extend `jobTargetColumns`/`jobTargetColumnsQualified`/`scanJobTargets` for the 2 new columns; add `SetTargetOwner`, `ListTargetsByOwner`.
- **Modify** `orchestrator/internal/notifications/types.go` — add `EventTargetAssigned`.
- **Create** `orchestrator/internal/api/job_target_handlers.go` — `AssignJobTarget`, `GetJobTargetsByOwner`.
- **Modify** `orchestrator/internal/api/routes.go` — 2 new routes.
- **Modify** `orchestrator/internal/api/rbac_matrix_test.go` — 2 new rows.
- **Test** `orchestrator/internal/jobs/store_test.go` (extended), `orchestrator/internal/api/job_target_handlers_test.go` (new).

---

### Task 1: Data model — ownership columns on `job_targets`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append after the `notification_webhooks` table, end of the `stmts` slice added in Sub-project 11)
- Modify: `orchestrator/internal/jobs/types.go` (`JobTarget` struct, currently lines 46-58)
- Modify: `orchestrator/internal/jobs/store.go` (`jobTargetColumns` line 79, `scanJobTargets` lines 65-77, `jobTargetColumnsQualified` lines 122-128)
- Test: `orchestrator/internal/jobs/store_test.go`

**Interfaces:**
- Produces: `jobs.JobTarget.OwnerID string`, `jobs.JobTarget.AssignedAt *time.Time` — every later task and every existing `List*`/`Mark*` caller that returns a `JobTarget` picks these up automatically once `scanJobTargets` is extended, with zero changes needed at those call sites.

- [ ] **Step 1: Write the failing test**

Add to `internal/jobs/store_test.go`:

```go
func TestJobTarget_OwnershipColumnsScanCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-own-1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if targets[0].OwnerID != "" || targets[0].AssignedAt != nil {
			t.Fatalf("new target = %+v, want unassigned by default (OwnerID=\"\", AssignedAt=nil)", targets[0])
		}

		mustExecJobsNotif(t, pool, `UPDATE job_targets SET owner_id=$1, assigned_at=NOW() WHERE id=$2`, "user-42", targets[0].ID)

		got, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets after raw update: %v", err)
		}
		if got[0].OwnerID != "user-42" || got[0].AssignedAt == nil {
			t.Fatalf("got = %+v, want OwnerID=user-42 AssignedAt set", got[0])
		}
	})
}
```

`mustExecJobsNotif` already exists in `internal/jobs/dispatch_test.go` (added in Sub-project 11) — same package, reused directly, no new helper needed.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/jobs/... -run TestJobTarget_OwnershipColumnsScanCorrectly -v`
Expected: FAIL — `column "owner_id" of relation "job_targets" does not exist` (the raw `UPDATE` in the test hits a column that doesn't exist yet).

- [ ] **Step 3: Add the columns to `postgres.go`**

Insert after the `notification_webhooks` table block (the last entry in the `stmts` slice, added in Sub-project 11), before the closing `}`:

```go
		// Sub-project 12 (Phase 8): Job-Target Ownership. See
		// docs/superpowers/specs/2026-08-05-job-target-ownership-design.md.
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS owner_id    text NOT NULL DEFAULT ''`,
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS assigned_at timestamptz`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_owner_id ON job_targets (owner_id) WHERE owner_id != ''`,
	}
```

(Replace the plan's closing `}` in your edit with whatever the file's actual last line is — this must be the final entry before the slice's closing brace, not a new slice.)

- [ ] **Step 4: Add the fields to `JobTarget`**

In `internal/jobs/types.go`, modify the struct (currently lines 46-58):

```go
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
	OwnerID     string     // "" = unassigned, matches this codebase's requested_by/approved_by convention
	AssignedAt  *time.Time // nil when OwnerID == ""
}
```

- [ ] **Step 5: Extend `jobTargetColumns`, `jobTargetColumnsQualified`, and `scanJobTargets`**

In `internal/jobs/store.go`:

```go
const jobTargetColumns = `id, job_id, agent_id, state, ref_id, error, retry_count, max_retries, created_at, started_at, completed_at, owner_id, assigned_at`
```

```go
func jobTargetColumnsQualified() string {
	return `jt.id, jt.job_id, jt.agent_id, jt.state, jt.ref_id, jt.error, jt.retry_count, jt.max_retries, jt.created_at, jt.started_at, jt.completed_at, jt.owner_id, jt.assigned_at`
}
```

```go
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
```

This single shared function/const pair is used by every existing `List*` method (`ListTargets`, `ListActiveDispatchedTargets`, `ListPendingTargetsAcrossActiveJobs`, `ListDeferredTargets`) — none of those call sites need any other change.

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/jobs/... -run TestJobTarget_OwnershipColumnsScanCorrectly -v`
Expected: PASS

- [ ] **Step 7: Run the full existing `internal/jobs` suite to confirm no regression**

Run: `go test ./internal/jobs/... -v 2>&1 | tail -60`
Expected: every pre-existing test still passes — confirms the column-list change didn't break any existing `Scan` call ordering.

- [ ] **Step 8: Commit**

```bash
git add internal/db/postgres.go internal/jobs/types.go internal/jobs/store.go internal/jobs/store_test.go
git commit -m "feat(jobs): add owner_id/assigned_at columns to job_targets"
git push
```

---

### Task 2: `Store.SetTargetOwner` and `Store.ListTargetsByOwner`

**Files:**
- Modify: `orchestrator/internal/jobs/store.go` (add after `MarkTargetPending`, currently lines 163-168)
- Test: `orchestrator/internal/jobs/store_test.go`

**Interfaces:**
- Consumes: `jobs.JobTarget` with `OwnerID`/`AssignedAt` (Task 1), `jobTargetColumns`/`scanJobTargets` (Task 1).
- Produces: `(*Store).SetTargetOwner(ctx, targetID, ownerID string) (JobTarget, error)`, `(*Store).ListTargetsByOwner(ctx, ownerID, state string) ([]JobTarget, error)`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/jobs/store_test.go`:

```go
func TestSetTargetOwner_AssignsThenClears(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-so-1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}

		assigned, err := store.SetTargetOwner(ctx, targets[0].ID, "user-7")
		if err != nil {
			t.Fatalf("SetTargetOwner (assign): %v", err)
		}
		if assigned.OwnerID != "user-7" || assigned.AssignedAt == nil {
			t.Fatalf("assigned = %+v, want OwnerID=user-7 AssignedAt set", assigned)
		}

		cleared, err := store.SetTargetOwner(ctx, targets[0].ID, "")
		if err != nil {
			t.Fatalf("SetTargetOwner (clear): %v", err)
		}
		if cleared.OwnerID != "" || cleared.AssignedAt != nil {
			t.Fatalf("cleared = %+v, want OwnerID=\"\" AssignedAt=nil", cleared)
		}
	})
}

func TestSetTargetOwner_NoSuchTarget_ReturnsErrNoRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, err := store.SetTargetOwner(context.Background(), "no-such-target-id", "user-1")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want pgx.ErrNoRows", err)
		}
	})
}

func TestListTargetsByOwner_ReturnsOnlyThatOwnerAcrossJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		jobA, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-lto-a"})
		if err != nil {
			t.Fatalf("CreateBatch A: %v", err)
		}
		jobB, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-lto-b"})
		if err != nil {
			t.Fatalf("CreateBatch B: %v", err)
		}
		targetsA, _ := store.ListTargets(ctx, jobA.ID)
		targetsB, _ := store.ListTargets(ctx, jobB.ID)

		if _, err := store.SetTargetOwner(ctx, targetsA[0].ID, "owner-x"); err != nil {
			t.Fatalf("SetTargetOwner A: %v", err)
		}
		if _, err := store.SetTargetOwner(ctx, targetsB[0].ID, "owner-x"); err != nil {
			t.Fatalf("SetTargetOwner B: %v", err)
		}

		got, err := store.ListTargetsByOwner(ctx, "owner-x", "")
		if err != nil {
			t.Fatalf("ListTargetsByOwner: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d targets, want 2 (one from each job)", len(got))
		}
	})
}

func TestListTargetsByOwner_StateFilterNarrows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-sfn-1", "agent-sfn-2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		store.SetTargetOwner(ctx, targets[0].ID, "owner-y")
		store.SetTargetOwner(ctx, targets[1].ID, "owner-y")
		if err := store.MarkTargetTerminal(ctx, targets[1].ID, TargetStateFailed, "boom"); err != nil {
			t.Fatalf("MarkTargetTerminal: %v", err)
		}

		got, err := store.ListTargetsByOwner(ctx, "owner-y", TargetStateFailed)
		if err != nil {
			t.Fatalf("ListTargetsByOwner: %v", err)
		}
		if len(got) != 1 || got[0].ID != targets[1].ID {
			t.Fatalf("got %+v, want exactly the failed target", got)
		}
	})
}

func TestListTargetsByOwner_NoAssignments_ReturnsEmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		got, err := store.ListTargetsByOwner(context.Background(), "nobody-owns-anything", "")
		if err != nil {
			t.Fatalf("ListTargetsByOwner: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %+v, want empty", got)
		}
	})
}
```

`store_test.go`'s current import block (verified fresh, not from memory) is:

```go
import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)
```

Add `"errors"` (stdlib group) and `"github.com/jackc/pgx/v5"` (third-party group, alongside the existing `pgxpool` import) — both are new to this file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/jobs/... -run 'TestSetTargetOwner_AssignsThenClears|TestSetTargetOwner_NoSuchTarget_ReturnsErrNoRows|TestListTargetsByOwner_ReturnsOnlyThatOwnerAcrossJobs|TestListTargetsByOwner_StateFilterNarrows|TestListTargetsByOwner_NoAssignments_ReturnsEmptySlice' -v`
Expected: FAIL — `undefined: SetTargetOwner` / `undefined: ListTargetsByOwner`.

- [ ] **Step 3: Implement both methods**

Add to `internal/jobs/store.go`, after `MarkTargetPending` (currently lines 163-168):

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/jobs/... -run 'TestSetTargetOwner_AssignsThenClears|TestSetTargetOwner_NoSuchTarget_ReturnsErrNoRows|TestListTargetsByOwner_ReturnsOnlyThatOwnerAcrossJobs|TestListTargetsByOwner_StateFilterNarrows|TestListTargetsByOwner_NoAssignments_ReturnsEmptySlice' -v`
Expected: PASS (all 5)

- [ ] **Step 5: Commit**

```bash
git add internal/jobs/store.go internal/jobs/store_test.go
git commit -m "feat(jobs): add SetTargetOwner and ListTargetsByOwner"
git push
```

---

### Task 3: API surface — assign endpoint, query endpoint, notification

**Files:**
- Modify: `orchestrator/internal/notifications/types.go` (add `EventTargetAssigned`, currently lines 7-16)
- Create: `orchestrator/internal/api/job_target_handlers.go`
- Modify: `orchestrator/internal/api/routes.go` (append after the `notification-webhooks` routes, currently lines 508-510)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (append after the `notification-webhooks` rows, currently lines 277-279)
- Test: `orchestrator/internal/api/job_target_handlers_test.go`

**Interfaces:**
- Consumes: `jobs.Store.SetTargetOwner`/`ListTargetsByOwner` (Task 2), `notifications.Event`/`Severity`/`SeverityInfo` (Sub-project 11), `h.jobsStore`/`h.notifications`/`h.auditLog` (existing `Handler` fields/methods).
- Produces: `(*Handler).AssignJobTarget`, `(*Handler).GetJobTargetsByOwner`.

- [ ] **Step 1: Add `EventTargetAssigned` to `notifications/types.go`**

Modify the `EventType` const block (currently lines 7-16):

```go
const (
	EventJobStarted   EventType = "job_started"
	EventJobCompleted EventType = "job_completed"
	EventJobPartial   EventType = "job_partially_completed"
	EventJobFailed    EventType = "job_failed"
	EventJobCancelled EventType = "job_cancelled"

	EventTargetFailed   EventType = "target_failed"
	EventTargetDeferred EventType = "target_deferred"
	EventTargetAssigned EventType = "target_assigned"
)
```

- [ ] **Step 2: Write the failing tests**

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

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestAssignJobTarget_SetsOwnerAndEmitsNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ajt-a1', 'AJT-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"ajt-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := jobsStore.ListTargets(context.Background(), job.ID)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithNotifications(notifStore)

		body, _ := json.Marshal(map[string]string{"ownerId": "user-99"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "targetId", targets[0].ID)
		w := httptest.NewRecorder()
		h.AssignJobTarget(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		got, err := jobsStore.ListTargets(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if got[0].OwnerID != "user-99" || got[0].AssignedAt == nil {
			t.Fatalf("got = %+v, want OwnerID=user-99 AssignedAt set", got[0])
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{JobID: job.ID, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 || events[0].Type != notifications.EventTargetAssigned {
			t.Fatalf("events = %+v, want exactly one target_assigned event", events)
		}
	})
}

func TestAssignJobTarget_ClearingOwnerEmitsNoNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ajt-a2', 'AJT-A2')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"ajt-a2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := jobsStore.ListTargets(context.Background(), job.ID)
		if _, err := jobsStore.SetTargetOwner(context.Background(), targets[0].ID, "user-99"); err != nil {
			t.Fatalf("SetTargetOwner: %v", err)
		}

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithNotifications(notifStore)

		body, _ := json.Marshal(map[string]string{"ownerId": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "targetId", targets[0].ID)
		w := httptest.NewRecorder()
		h.AssignJobTarget(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{JobID: job.ID, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("events = %+v, want none for a clear-ownership action", events)
		}
	})
}

func TestAssignJobTarget_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		body, _ := json.Marshal(map[string]string{"ownerId": "user-1"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "targetId", "no-such-target")
		w := httptest.NewRecorder()
		h.AssignJobTarget(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestGetJobTargetsByOwner_ReturnsAcrossJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gjt-a1', 'GJT-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"gjt-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := jobsStore.ListTargets(context.Background(), job.ID)
		if _, err := jobsStore.SetTargetOwner(context.Background(), targets[0].ID, "owner-q"); err != nil {
			t.Fatalf("SetTargetOwner: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := httptest.NewRequest(http.MethodGet, "/api/job-targets?ownerId=owner-q", nil)
		w := httptest.NewRecorder()
		h.GetJobTargetsByOwner(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Targets []jobs.JobTarget `json:"targets"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Targets) != 1 || resp.Targets[0].OwnerID != "owner-q" {
			t.Fatalf("got %+v, want exactly the one owned target", resp.Targets)
		}
	})
}

func TestGetJobTargetsByOwner_MissingOwnerId_400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := httptest.NewRequest(http.MethodGet, "/api/job-targets", nil)
		w := httptest.NewRecorder()
		h.GetJobTargetsByOwner(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/api/... -run 'TestAssignJobTarget|TestGetJobTargetsByOwner' -v`
Expected: FAIL — `h.AssignJobTarget undefined` / `h.GetJobTargetsByOwner undefined`.

- [ ] **Step 4: Write `job_target_handlers.go`**

```go
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/notifications"
)

// AssignJobTarget assigns or clears a JobTarget's owner. An empty ownerId
// clears ownership; assigning a non-empty owner emits a Phase 7
// EventTargetAssigned notification so the new owner is alerted.
// POST /api/job-targets/{targetId}/assign  body: {ownerId}
func (h *Handler) AssignJobTarget(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	targetID := chi.URLParam(r, "targetId")
	var req struct {
		OwnerID string `json:"ownerId"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	target, err := h.jobsStore.SetTargetOwner(r.Context(), targetID, req.OwnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, "job target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.OwnerID != "" && h.notifications != nil {
		h.notifications.Emit(r.Context(), notifications.Event{
			Type: notifications.EventTargetAssigned, JobID: target.JobID, TargetID: target.ID, AgentID: target.AgentID,
			Severity: notifications.SeverityInfo, Message: "assigned to " + req.OwnerID,
			Metadata: map[string]any{"ownerId": req.OwnerID},
		})
	}
	h.auditLog(r, "jobs.target_assigned", targetID, map[string]any{"ownerId": req.OwnerID}, "ok")
	respond(w, map[string]any{"target": target})
}

// GetJobTargetsByOwner lists every JobTarget assigned to ownerId, across
// every job, most-recently-assigned first. Optional state query param
// narrows to one TargetState value.
// GET /api/job-targets?ownerId=X&state=Y
func (h *Handler) GetJobTargetsByOwner(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	ownerID := r.URL.Query().Get("ownerId")
	if ownerID == "" {
		jsonError(w, "ownerId is required", http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	targets, err := h.jobsStore.ListTargetsByOwner(r.Context(), ownerID, state)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"targets": targets})
}
```

- [ ] **Step 5: Register the 2 routes**

In `internal/api/routes.go`, add after the existing `notification-webhooks` routes (currently lines 508-510):

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/job-targets/{targetId}/assign", h.AssignJobTarget)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/job-targets", h.GetJobTargetsByOwner)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestAssignJobTarget|TestGetJobTargetsByOwner' -v`
Expected: PASS (all 5)

- [ ] **Step 7: Add RBAC matrix rows**

In `internal/api/rbac_matrix_test.go`, add after the existing `notification-webhooks` rows (currently lines 277-279):

```go
	{http.MethodPost, "/api/job-targets/{targetId}/assign", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/job-targets", tierPermission, auth.CanExecuteRemediation},
```

Run: `go test ./internal/api/... -run TestRBACMatrix -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/notifications/types.go internal/api/job_target_handlers.go internal/api/job_target_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add job-target ownership assign/query endpoints"
git push
```

---

### Task 4: Full suite verification

**Files:** none (verification only).

- [ ] **Step 1: Build the full binary**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 2: Run the full test suite**

Run: `go test ./... 2>&1 | tail -100`
Expected: no `FAIL` lines. If a package fails, re-run that specific package alone before concluding it's a real regression — this environment has now shown Docker/testcontainer resource contention on full-suite runs three separate times (see `project_endpoint_health_remediation` memory's recurring-gotchas section); treat it as expected baseline noise, not evidence of a bug, until an isolated re-run of the same package also fails.

- [ ] **Step 3: Report completion**

No commit for this task (verification only) — if Step 2 required a fix, that fix gets its own commit before this task is considered done.

---

## Self-Review Notes (fixed inline, listed here for the executing engineer's awareness)

- **Spec coverage:** All 5 spec sections (grounding, data model, assignment API, notification integration, query surface, testing) map onto Tasks 1-3. Task 4 covers the spec's implicit "no regressions" requirement.
- **Shared-scan-function leverage confirmed:** `jobTargetColumns`/`jobTargetColumnsQualified`/`scanJobTargets` are each used by exactly the 4 existing `List*` methods plus the 2 new ones added in Task 2 — verified during plan-writing by grepping every call site, so Task 1's single edit point is genuinely sufficient and no `List*` method needs individual changes.
- **`pgx.ErrNoRows` behavior confirmed:** `SetTargetOwner`'s `UPDATE ... RETURNING` + `QueryRow().Scan()` shape is new to this codebase (no prior `UPDATE...RETURNING` precedent in `internal/jobs/store.go` — every existing `Mark*` method uses a bare `Exec`), but the `pgx.ErrNoRows`-on-zero-rows behavior is standard `pgx` `QueryRow` semantics already relied on elsewhere in this codebase's `INSERT ... RETURNING id` calls (e.g. `CreateBatchScheduled`).
- **Type consistency check:** `JobTarget.OwnerID`/`AssignedAt` (Task 1) are read by `SetTargetOwner`/`ListTargetsByOwner` (Task 2) and by `AssignJobTarget`/`GetJobTargetsByOwner` (Task 3) — field names and the `*time.Time` nil-means-unassigned convention are used identically across all three tasks.
