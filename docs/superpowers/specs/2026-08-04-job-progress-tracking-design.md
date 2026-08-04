# Job Progress Tracking (Phase 4) — Design

## 1. Problem statement

`GET /api/jobs/{jobId}` already returns every `JobTarget` row for a job (Sub-project 6), so a client *can* compute "312 of 500 done" today — but only by fetching and counting every target row itself, on every poll. For a large fleet job (hundreds or thousands of targets), that's real, repeated, wasted work, and every polling client duplicates the same counting logic. Phase 4 moves that computation server-side: a compact progress summary computed once per request from a grouped count, not from fetching individual rows.

## 2. Scope

**In scope:**
- `jobs.JobProgress` — a computed summary of one job's target-state distribution, plus a completion percentage.
- `Store.ComputeProgress(ctx, jobID) (JobProgress, error)` — computed via a `GROUP BY state` SQL query, never fetching individual target rows.
- `GetJob`'s response gains a new `progress` key, additive alongside the existing `job`/`targets` keys.

**Explicitly out of scope, deferred:**
- Any new database table or column — fully compute-on-read, no persisted counters.
- A fleet-wide `GET /api/jobs` list-with-progress endpoint — no such list endpoint exists today; adding one is a separate concern (pagination, filtering by type/state/date) that would inflate this phase's scope.
- Any frontend/UI — backend-only, consistent with every prior sub-project in this initiative. A dashboard can consume the new `progress` field once it exists.

## 3. Architecture

**Compute-on-read, not persisted counters.** This codebase consistently favors derived state over denormalized state: `jobs.AggregateState` (Sub-project 6), `models.ComputeScore`, and `driftanalytics.ComputeDriftStats` (Sub-project 9) all recompute from the raw source on every read rather than maintaining running counters. Persisted columns like `jobs.completed_count`/`jobs.failed_count` would need to be updated atomically on every target-state transition, across every code path that ever calls `MarkTargetDispatched`/`MarkTargetTerminal`/`MarkTargetDeferred`/`MarkTargetPending` (Sub-project 6/7) — a real source of drift if any path is missed or a transaction partially fails. A grouped count query has no such failure mode: it's always consistent with `job_targets`' actual current state, by construction.

**Lives in `internal/jobs`, not `internal/api`.** Progress is a property of any job, regardless of job type (`batch_remediation`, `bas_revalidation`, or any future type) — the same reasoning that put `AggregateState` in `internal/jobs` rather than duplicated per-consumer in `internal/api`. `internal/jobs` still never imports `internal/api`.

**A single grouped-count query scales to any target count.** `SELECT state, COUNT(*) FROM job_targets WHERE job_id=$1 GROUP BY state` returns at most 6 rows (one per `TargetState*` value) regardless of whether the job has 20 targets or 20,000 — a materially different cost profile than `ListTargets`, which returns one row per target and is what `GetJob` already uses for the (unchanged, still-returned) full target list.

**Terminal-based completion percentage.** `PercentComplete` is defined as `(Completed + Failed + Cancelled) / Total * 100` — the fraction of targets that have reached a terminal state, independent of whether they succeeded. This was a deliberate choice over `Completed / Total`: a job where every target has failed is still *done* (100% terminal), and a progress bar that stays at 0% forever on a fully-failed job would be misleading about what "progress" means. `Deferred` targets (Sub-project 7's frozen-target state) are non-terminal — like `Pending`/`Dispatched`, they still count toward "not yet done."

## 4. Data model

No new tables or columns. One new file, `internal/jobs/progress.go`:

```go
// internal/jobs/progress.go
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
```

## 5. Computation

```go
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

The `switch` on `state` deliberately uses the existing `TargetState*` constants (never a bare `"running"` — confirmed `job_targets.state` never takes that value; `"running"` is a `Job`-level state, `JobStateRunning`, not a target one) rather than trusting the raw SQL string, so an unexpected future state value falls through silently counted in `Total` but not in any named bucket, rather than panicking or erroring.

## 6. API surface

`GetJob` (`internal/api/job_handlers.go`) gains one call and one response key — fully additive:

```go
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

No new endpoint, no new permission — rides on `GetJob`'s existing `auth.CanExecuteRemediation` gate (unchanged route registration).

## 7. Error handling

- **Job has zero targets** (shouldn't happen in practice — every job is created with at least one target — but defensively handled) — `Total == 0`, every count 0, `PercentComplete` stays 0 rather than dividing by zero.
- **`ComputeProgress` query error** — `GetJob` returns 500, matching its existing error-handling pattern for `Get`/`ListTargets` failures; progress is not optional/best-effort, since a caller relying on it for a progress bar would rather see an explicit failure than silently-wrong zeros.
- **Unknown target state value** (a future job type introduces a state not in `TargetState*`) — counted in `Total` but not in any named bucket, so `Total` stays accurate even if a bucket sum wouldn't equal it; not treated as an error, since `internal/jobs` should never reject valid data just because a caller's Go code hasn't been updated for a new state yet.

## 8. Testing

- **`ComputeProgress`**: DB-backed tests (this function does real SQL, unlike Sub-project 9's pure `ComputeDriftStats`) — a job with a mix of all 6 target states, asserting each bucket count and `PercentComplete`; a job with zero targets (if constructible) or a nonexistent `jobID` asserting `Total == 0` and no error; a job where every target is `failed` asserting `PercentComplete == 100` (the "fully done, fully failed" case that motivated the terminal-based definition).
- **`GetJob`**: no dedicated test exists for this handler today (confirmed: `job_handlers_test.go` exercises `CreateBatchRemediationJob` and `CancelJob` directly, but reaches `GetJob` only indirectly if at all) — add one new test seeding a job with a known mix of target states and asserting the response's `progress` key matches.

## 9. Explicitly deferred

A fleet-wide jobs-list endpoint and any frontend/UI work are deferred, not cut — `JobProgress` has no structural blocker to being reused by a future `GET /api/jobs` list endpoint (called once per job in the list) or by a dashboard once one exists.
