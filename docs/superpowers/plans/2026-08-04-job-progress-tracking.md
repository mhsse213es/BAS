# Job Progress Tracking (Phase 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `GET /api/jobs/{jobId}` returns a computed progress summary (per-state counts + completion percentage) alongside its existing `job`/`targets` keys, without a client having to fetch and count every target row itself.

**Architecture:** A new `Store.ComputeProgress` method in `internal/jobs` derives `JobProgress` from a single `GROUP BY state` query over `job_targets` — no persisted counters, no new table, matching `AggregateState`/`ComputeScore`/`ComputeDriftStats`'s established compute-on-read precedent. `GetJob` calls it and adds one new response key.

**Tech Stack:** Go, PostgreSQL (pgx) — matches every prior sub-project in this initiative.

## Global Constraints

- No new database tables or columns — fully compute-on-read.
- `PercentComplete = (Completed + Failed + Cancelled) / Total * 100` — terminal-based, not success-based; a fully-failed job is 100% complete, not 0%.
- `Deferred` targets count as non-terminal (like `Pending`/`Dispatched`), matching Sub-project 7's existing "deferred is not done" semantics.
- No new permission — `GetJob`'s existing `auth.CanExecuteRemediation` gate is unchanged.
- Direct commits to `main`, no branches/PRs, per this repo's established convention.
- Every task follows TDD: write failing test → verify it fails → implement → verify it passes → commit.

---

### Task 1: `JobProgress` type and `Store.ComputeProgress`

**Files:**
- Create: `orchestrator/internal/jobs/progress.go`
- Create: `orchestrator/internal/jobs/progress_test.go`

**Interfaces:**
- Consumes: `Store.CreateBatch`, `Store.ListTargets`, `Store.MarkTargetDispatched(ctx, targetID, refID string) error`, `Store.MarkTargetTerminal(ctx, targetID, state, errText string) error`, `Store.MarkTargetDeferred(ctx, targetID, reason string) error` (all Sub-project 6/7, unchanged) — used only to seed test fixtures.
- Produces: `JobProgress{Total, Pending, Dispatched, Completed, Failed, Cancelled, Deferred int; PercentComplete float64}`, `Store.ComputeProgress(ctx context.Context, jobID string) (JobProgress, error)` — both consumed by Task 2.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/jobs/progress_test.go`:
```go
package jobs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestComputeProgress_CountsEveryTargetState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1",
			[]string{"pg-a1", "pg-a2", "pg-a3", "pg-a4", "pg-a5", "pg-a6"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 6 {
			t.Fatalf("got %d targets, want 6", len(targets))
		}

		// targets[0] stays pending.
		if err := store.MarkTargetDispatched(ctx, targets[1].ID, "ref-1"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}
		if err := store.MarkTargetTerminal(ctx, targets[2].ID, TargetStateCompleted, ""); err != nil {
			t.Fatalf("MarkTargetTerminal(completed): %v", err)
		}
		if err := store.MarkTargetTerminal(ctx, targets[3].ID, TargetStateFailed, "boom"); err != nil {
			t.Fatalf("MarkTargetTerminal(failed): %v", err)
		}
		if err := store.MarkTargetTerminal(ctx, targets[4].ID, TargetStateCancelled, ""); err != nil {
			t.Fatalf("MarkTargetTerminal(cancelled): %v", err)
		}
		if err := store.MarkTargetDeferred(ctx, targets[5].ID, "frozen"); err != nil {
			t.Fatalf("MarkTargetDeferred: %v", err)
		}

		progress, err := store.ComputeProgress(ctx, job.ID)
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		want := JobProgress{Total: 6, Pending: 1, Dispatched: 1, Completed: 1, Failed: 1, Cancelled: 1, Deferred: 1, PercentComplete: 50}
		if progress != want {
			t.Errorf("progress = %+v, want %+v", progress, want)
		}
	})
}

func TestComputeProgress_AllFailed_Is100PercentComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"pg-b1", "pg-b2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		for _, tg := range targets {
			if err := store.MarkTargetTerminal(ctx, tg.ID, TargetStateFailed, "boom"); err != nil {
				t.Fatalf("MarkTargetTerminal: %v", err)
			}
		}

		progress, err := store.ComputeProgress(ctx, job.ID)
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		if progress.PercentComplete != 100 {
			t.Errorf("PercentComplete = %v, want 100 (fully terminal, even though every target failed)", progress.PercentComplete)
		}
	})
}

func TestComputeProgress_NoSuchJob_ReturnsZeroValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		progress, err := store.ComputeProgress(context.Background(), "no-such-job-id")
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		if progress.Total != 0 || progress.PercentComplete != 0 {
			t.Errorf("progress = %+v, want all-zero for a job with no targets", progress)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestComputeProgress -v`
Expected: FAIL to compile — `JobProgress`/`ComputeProgress` don't exist yet.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/jobs/progress.go`:
```go
package jobs

import "context"

// JobProgress is a computed summary of one job's target-state
// distribution -- never persisted, always derived fresh from job_targets.
type JobProgress struct {
	Total           int
	Pending         int
	Dispatched      int
	Completed       int
	Failed          int
	Cancelled       int
	Deferred        int
	PercentComplete float64 // (Completed+Failed+Cancelled) / Total * 100; 0 if Total == 0
}

// ComputeProgress derives one job's JobProgress via a grouped count over
// job_targets -- at most 6 rows regardless of target count, never fetches
// individual target rows.
func (s *Store) ComputeProgress(ctx context.Context, jobID string) (JobProgress, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT state, COUNT(*) FROM job_targets WHERE job_id=$1 GROUP BY state`, jobID)
	if err != nil {
		return JobProgress{}, err
	}
	defer rows.Close()

	var p JobProgress
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return JobProgress{}, err
		}
		switch state {
		case TargetStatePending:
			p.Pending = count
		case TargetStateDispatched:
			p.Dispatched = count
		case TargetStateCompleted:
			p.Completed = count
		case TargetStateFailed:
			p.Failed = count
		case TargetStateCancelled:
			p.Cancelled = count
		case TargetStateDeferred:
			p.Deferred = count
		}
		p.Total += count
	}
	if err := rows.Err(); err != nil {
		return JobProgress{}, err
	}
	if p.Total > 0 {
		terminal := p.Completed + p.Failed + p.Cancelled
		p.PercentComplete = float64(terminal) / float64(p.Total) * 100
	}
	return p, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestComputeProgress -v`
Expected: PASS

- [ ] **Step 5: Run the full `internal/jobs` package suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/jobs/progress.go orchestrator/internal/jobs/progress_test.go
git commit -m "feat(jobs): add ComputeProgress -- grouped target-state count, no persisted counters"
```

---

### Task 2: Wire `progress` into `GetJob`

**Files:**
- Modify: `orchestrator/internal/api/job_handlers.go`
- Modify: `orchestrator/internal/api/job_handlers_test.go`

**Interfaces:**
- Consumes: `jobs.JobProgress`, `h.jobsStore.ComputeProgress` (Task 1).
- Produces: `GetJob`'s response gains a `progress` key.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/job_handlers_test.go`:
```go
func TestGetJob_IncludesProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gj-a1', 'GJ-A1')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gj-a2', 'GJ-A2')`)

		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"gj-a1", "gj-a2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := jobsStore.ListTargets(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if err := jobsStore.MarkTargetTerminal(context.Background(), targets[0].ID, jobs.TargetStateCompleted, ""); err != nil {
			t.Fatalf("MarkTargetTerminal: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.GetJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var resp struct {
			Progress jobs.JobProgress `json:"progress"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Progress.Total != 2 || resp.Progress.Completed != 1 || resp.Progress.Pending != 1 {
			t.Errorf("progress = %+v, want Total=2 Completed=1 Pending=1", resp.Progress)
		}
		if resp.Progress.PercentComplete != 50 {
			t.Errorf("PercentComplete = %v, want 50", resp.Progress.PercentComplete)
		}
	})
}
```

Check `job_handlers_test.go`'s existing imports (`context`, `encoding/json`, `net/http`, `net/http/httptest`, `jobs`, `scenario`, `ws`, `pgxpool`) — all already present from earlier tasks in this file.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestGetJob_IncludesProgress -v`
Expected: FAIL — the response has no `progress` key yet, so `resp.Progress` stays its zero value and the `Total != 2` assertion fails.

- [ ] **Step 3: Implement**

In `orchestrator/internal/api/job_handlers.go`, change `GetJob`:
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
	progress, err := h.jobsStore.ComputeProgress(r.Context(), jobID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"job": job, "targets": targets, "progress": progress})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestGetJob_IncludesProgress -v`
Expected: PASS

- [ ] **Step 5: Run the full `job_handlers_test.go` coverage to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetJob|TestCreateBatchRemediationJob|TestCancelJob" -v`
Expected: all PASS — `GetJob`'s response gained a key, existing `job`/`targets` keys are untouched, so no prior consumer of this endpoint breaks.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/job_handlers.go orchestrator/internal/api/job_handlers_test.go
git commit -m "feat(api): include progress summary in GetJob response"
```

---

### Task 3: Full suite verification

**Files:** none (verification-only task).

- [ ] **Step 1: Run the full orchestrator test suite**

Run: `cd orchestrator && go build ./... && go test ./...`
Expected: builds clean, all tests PASS. If a package fails only under full-suite concurrency (Docker/testcontainer resource contention — seen with `internal/connector` in Sub-project 8 and `internal/api` in Sub-project 9), re-run that specific package alone before concluding it's a real regression.

- [ ] **Step 2: If any test fails, apply superpowers:systematic-debugging**

Do not patch symptoms — find root cause per that skill's process before making any fix.

- [ ] **Step 3: Update project memory**

This step is a reminder for the session, not a code change: once the full suite is green, update `project_endpoint_health_remediation.md` with a new "Sub-project 10 — Job Progress Tracking (Phase 4)" section (mirroring the existing Sub-project 6/7/8/9 entries' level of detail) and refresh `MEMORY.md`'s index line.
