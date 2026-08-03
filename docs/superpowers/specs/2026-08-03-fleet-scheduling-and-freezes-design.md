# Fleet Scheduling & Maintenance Freezes (Sub-project 7, Phases 3+10) — Design

## 1. Problem statement

Sub-project 6 built the generic `Job`/`JobTarget` engine and proved it with one consumer (batch remediation), but every job dispatches immediately and unconditionally. Two capabilities from the original 10-phase proposal are the next highest-priority pieces: Phase 3 (Tier 3 scheduled/maintenance-window remediation — the hard dependency several later phases wait on) and Phase 10 (exceptions — a target under maintenance freeze shouldn't block or corrupt a fleet job's outcome). They're bundled into one sub-project because both extend the exact same touchpoint — `Dispatcher.Tick()`'s target-selection step — and Phase 10's "maintenance freeze" is conceptually the inverse of Phase 3's "maintenance window": one says *don't dispatch this job before X*, the other says *don't dispatch to this agent until X clears*.

## 2. Scope

**In scope:**
- `Job.ScheduledAt` — a one-shot future dispatch time on any job.
- `job_schedules` — a recurring weekly (day-of-week + time-of-day + IANA timezone) template that spawns a fresh one-shot `Job` each occurrence, skipping (and logging) if the previous spawn is still non-terminal.
- `agent_maintenance_freezes` — a one-shot absolute `[from, to]` freeze window per agent, checked at dispatch time (not job-creation time).
- `TargetStateDeferred` — a new non-terminal `JobTarget` state for a target caught by a freeze at dispatch time; auto-resumes (flips back to `pending`) the moment its freeze lifts, with no operator action required.
- API surface: optional `scheduledAt` on batch-remediation job creation; full CRUD-ish surface for schedules and freezes.

**Explicitly out of scope, deferred:**
- Cron-expression or any recurrence shape beyond weekly day-of-week + time-of-day (confirmed: simple rule now, richer recurrence later if ever needed).
- Recurring freeze windows (confirmed: freezes stay one-shot absolute ranges).
- Group/label-based freezing (e.g. freeze every `env_label='Production'` agent at once) — explicit per-agent only.
- Hard-exclude semantics for frozen targets — only the auto-resume/deferred behavior described above.
- Notifications on schedule-skip, schedule-spawn, or freeze events (Phase 7).
- Persisted progress-count columns (Phase 4) — unrelated scope, not touched here.
- Any frontend/UI — this sub-project is backend/API only, consistent with every prior sub-project in this initiative.
- Migrating `internal/connector.Scheduler`, the ITSM revalidation loop, or `vexsweep` onto this machinery — untouched, as always.

## 3. Architecture

Both extensions turn out to be **generic infrastructure**, not remediation-specific, so `internal/jobs` owns `job_schedules` and `agent_maintenance_freezes` directly — any future job type (BAS revalidation jobs, scan jobs) gets schedulability and freeze-respect automatically, with zero per-consumer wiring. `internal/jobs` still never imports `internal/remediation` or `internal/api`.

`Job.ScheduledAt *time.Time` is the foundational primitive: `nil` means "dispatch immediately" (Sub-project 6's existing, unchanged behavior); a future value means `Tick()`'s pending-target query simply skips that job's targets until the time passes. No new `Job` state is needed for this — a scheduled job just sits in `requested` until its `ScheduledAt` arrives, then dispatches exactly like any other job.

`job_schedules` sits *above* `Job` as a template, not a property of one job. A lightweight spawner (`Dispatcher.spawnDueSchedules`, run at the start of every `Tick()`) checks each enabled schedule's next weekly occurrence via a pure function, `nextOccurrenceSince`, and calls the existing `Store.CreateBatch` directly — spawning a job from a schedule needs no new dispatch machinery, it's the same `CreateBatch` Sub-project 6 already built.

`agent_maintenance_freezes` is checked at **dispatch time**, not job-creation time, so a freeze declared after a job already exists still correctly catches its not-yet-dispatched targets. A frozen target gets `TargetStateDeferred` instead of being dispatched; every later tick re-checks deferred targets and flips them back to `pending` the instant their freeze lifts, at which point the ordinary pending-dispatch step picks them up like any other target — no separate "resume" dispatch path. The job's aggregate state stays `running` for as long as any target is deferred.

## 4. Data model

```go
// internal/jobs/types.go
type Job struct {
    // ...existing fields (Sub-project 6)...
    ScheduledAt *time.Time // nil = dispatch immediately; non-nil = don't dispatch before this
}

const TargetStateDeferred = "deferred" // frozen at dispatch time; non-terminal, auto-resumes

// Schedule is a recurring template that spawns a fresh one-shot Job each
// weekly occurrence. It is not itself a Job -- it outlives any single
// spawned run.
type Schedule struct {
    ID               string
    Type             string
    Payload          json.RawMessage // same shape as Job.Payload
    AgentIDs         []string
    DayOfWeek        int    // 0=Sunday .. 6=Saturday
    TimeOfDay        string // "23:00", 24h HH:MM
    Timezone         string // IANA name, e.g. "Asia/Kolkata"; validated via time.LoadLocation
    Enabled          bool
    CreatedBy        string
    CreatedAt        time.Time
    LastOccurrenceAt *time.Time // most recent occurrence instant already handled (spawned OR skipped)
    LastSpawnedJobID string     // "" until the first successful spawn
}

// AgentFreeze is a one-shot absolute freeze window for one agent.
type AgentFreeze struct {
    ID        string
    AgentID   string
    FromAt    time.Time
    ToAt      time.Time
    Reason    string
    CreatedBy string
    CreatedAt time.Time
}
```

```sql
-- Job.ScheduledAt
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled_at timestamptz;

-- job_schedules
CREATE TABLE IF NOT EXISTS job_schedules (
    id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    type                text        NOT NULL,
    payload             jsonb       NOT NULL DEFAULT '{}',
    agent_ids           jsonb       NOT NULL,
    day_of_week         int         NOT NULL,
    time_of_day         text        NOT NULL,
    timezone            text        NOT NULL DEFAULT 'UTC',
    enabled             boolean     NOT NULL DEFAULT true,
    created_by          text        NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT NOW(),
    last_occurrence_at  timestamptz,
    last_spawned_job_id text        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_job_schedules_enabled ON job_schedules (enabled) WHERE enabled = true;

-- agent_maintenance_freezes
CREATE TABLE IF NOT EXISTS agent_maintenance_freezes (
    id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    agent_id   text        NOT NULL,
    from_at    timestamptz NOT NULL,
    to_at      timestamptz NOT NULL,
    reason     text        NOT NULL DEFAULT '',
    created_by text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_maintenance_freezes_agent_id ON agent_maintenance_freezes (agent_id);
```

`agent_ids`/`payload` on `job_schedules` are `jsonb` (not a normalized child table) — mirrors `Job.Payload`'s own free-form shape; the whole list is re-read as a unit on every spawn, never queried per-row, so a join table would add nothing but overhead.

## 5. Dispatch-loop mechanics

```go
// internal/jobs/dispatch.go
func (d *Dispatcher) Tick(ctx context.Context) error {
    d.spawnDueSchedules(ctx) // NEW: phase 0

    // phase 1: resolve terminal in-flight targets (Sub-project 6, unchanged)

    deferred, _ := d.store.ListDeferredTargets(ctx) // NEW: phase 2
    for _, t := range deferred {
        if frozen, _, _ := d.store.IsAgentFrozen(ctx, t.AgentID); !frozen {
            d.store.MarkTargetPending(ctx, t.ID) // back to pending; phase 3 picks it up, this tick or later
            touchedJobs[t.JobID] = true
        }
    }

    // phase 3: dispatch pending targets. ListPendingTargetsAcrossActiveJobs
    // now filters `j.scheduled_at IS NULL OR j.scheduled_at <= NOW()`. For each:
    //   if IsAgentFrozen(target.AgentID): MarkTargetDeferred(reason) instead of dispatching
    //   else: existing DispatchFn call, unchanged

    // phase 4: aggregate state -- AggregateState gains TargetStateDeferred
    // handling (counts like "dispatched": job stays running, never counts
    // toward completed/partial/failed).
}
```

Resuming a deferred target (phase 2) is a single cheap `UPDATE`, not a real dispatch, so it is **not** subject to `jobDispatchBatchSize` — only phase 3's actual `DispatchFn` calls are capped.

```go
func (d *Dispatcher) spawnDueSchedules(ctx context.Context) {
    schedules, err := d.store.ListEnabledSchedules(ctx)
    if err != nil {
        return
    }
    for _, sch := range schedules {
        occurrence, ok := nextOccurrenceSince(sch, time.Now().UTC())
        if !ok {
            continue // no new occurrence since sch.LastOccurrenceAt -- the common case
        }
        if sch.LastSpawnedJobID != "" {
            if job, err := d.store.Get(ctx, sch.LastSpawnedJobID); err == nil && !IsTerminalJobState(job.State) {
                d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, "") // skip + log, previous run still active
                continue
            }
        }
        newJob, err := d.store.CreateBatch(ctx, sch.Type, sch.Payload, sch.CreatedBy, sch.AgentIDs)
        if err == nil {
            d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, newJob.ID)
        }
    }
}

// IsTerminalJobState reports whether state is one Tick() will never advance
// further -- the overlap check above uses this to decide whether the
// previous spawn from a schedule is still active.
func IsTerminalJobState(state string) bool {
    return state == JobStateCompleted || state == JobStatePartial || state == JobStateFailed || state == JobStateCancelled
}

// nextOccurrenceSince finds the most recent past occurrence of sch's weekly
// (DayOfWeek, TimeOfDay) slot in sch.Timezone, and reports whether it is
// newer than sch.LastOccurrenceAt. ok=false is the common case (nothing new
// since the last check).
func nextOccurrenceSince(sch Schedule, now time.Time) (occurrence time.Time, ok bool) {
    loc, err := time.LoadLocation(sch.Timezone)
    if err != nil {
        return time.Time{}, false
    }
    nowLocal := now.In(loc)
    hh, mm, err := parseTimeOfDay(sch.TimeOfDay) // "23:00" -> 23, 0
    if err != nil {
        return time.Time{}, false
    }
    for daysBack := 0; daysBack < 7; daysBack++ {
        candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
        if int(candidate.Weekday()) != sch.DayOfWeek || candidate.After(now) {
            continue
        }
        if sch.LastOccurrenceAt != nil && !candidate.After(*sch.LastOccurrenceAt) {
            return time.Time{}, false // already handled
        }
        return candidate.UTC(), true
    }
    return time.Time{}, false
}
```

`IsAgentFrozen(ctx, agentID) (frozen bool, reason string, err error)` queries `agent_maintenance_freezes` directly: `WHERE agent_id=$1 AND from_at <= NOW() AND to_at >= NOW() ORDER BY created_at DESC LIMIT 1`. Overlapping freezes for the same agent are allowed (not rejected at creation) — the check only cares whether *any* freeze is currently active.

## 6. API surface

- `POST /api/jobs/batch-remediation` — gains an optional `scheduledAt` field (RFC3339 string). Omitted/empty → `Job.ScheduledAt` stays `nil`, dispatches immediately — fully backward compatible with Sub-project 6.
- `POST /api/job-schedules` — body `{remediationId, reason, agentIds, dayOfWeek, timeOfDay, timezone}`. Same tier-gated permission logic as `CreateBatchRemediationJob` (catalog lookup, Tier 4 rejection, Tier 2 → `CanApproveRemediation`) — a schedule is "create this batch job, but recurring," inheriting the identical policy rather than a new one. Validates `dayOfWeek` (0-6), `timeOfDay` (HH:MM), and `timezone` (`time.LoadLocation` must succeed) before creating the row.
- `GET /api/job-schedules` — list all schedules, `auth.CanExecuteRemediation` (matches `GetJob`'s precedent).
- `POST /api/job-schedules/{id}/cancel` — sets `enabled=false`. `auth.CanExecuteRemediation` (matches `CancelJob`'s precedent — no per-tier distinction for a cancel action).
- `POST /api/agents/{agentId}/maintenance-freezes` — body `{fromAt, toAt, reason}`. `auth.CanApproveRemediation` (Admin-only) — a freeze can silently block every remediation tier including ones an Analyst is normally allowed to run, making it a stronger action than executing a single remediation. Validates `toAt` is after `fromAt`.
- `GET /api/agents/{agentId}/maintenance-freezes` — list an agent's freezes, `auth.CanExecuteRemediation` (read-only).
- `DELETE /api/maintenance-freezes/{id}` — lift a freeze early. `auth.CanApproveRemediation` (same reasoning as create).

## 7. Error handling

- **Invalid schedule input** (bad `dayOfWeek`/`timeOfDay`/unresolvable `timezone`) — rejected at creation with 400, never written to `job_schedules`. `nextOccurrenceSince` itself never errors at runtime because invalid data can't get past creation-time validation; its own `time.LoadLocation`/`parseTimeOfDay` failure paths return `ok=false` defensively (treated as "nothing to spawn," not a crash) purely as defense-in-depth.
- **Spawn failure** (`CreateBatch` errors, e.g. transient DB issue) — `spawnDueSchedules` skips that schedule for this tick without advancing `last_occurrence_at`, so the same occurrence is retried on the next tick rather than silently lost.
- **Previous occurrence still running** — skipped and logged (`log.Printf`, matching the `[jobs]`/`[vexsweep]` logging convention already used in `main.go`), `last_occurrence_at` still advances so the skip isn't re-evaluated every tick for the rest of that occurrence's window.
- **Agent frozen at dispatch time** — target becomes `TargetStateDeferred` with `Error` set to the freeze's reason text (visible via `GET /api/jobs/{jobId}`), not treated as any kind of failure.
- **Freeze lifted mid-tick** — no race: phase 2 (resume-check) always runs before phase 3 (dispatch) within the same tick, so a target can transition deferred→pending→dispatched across at most two ticks (10s), never dispatched twice.

## 8. Testing

- **`nextOccurrenceSince`**: pure-function unit tests (no DB) — first occurrence, already-handled occurrence, timezone crossing a UTC day boundary (e.g. `Asia/Kolkata` Friday 23:00 IST is Friday 17:30 UTC, still the same UTC calendar day; a case where it *would* cross needs its own explicit test), invalid timezone, invalid time-of-day.
- **`AggregateState`**: extend Sub-project 6's existing table-driven tests with `TargetStateDeferred` cases (deferred-only → running, mix of completed+deferred → running, never completed/partial/failed while any target is deferred).
- **Dispatcher**: DB-backed tests for `spawnDueSchedules` (spawns on due occurrence, skips when previous spawn still non-terminal, respects `enabled=false`), and for the freeze defer/resume cycle (`ListPendingTargetsAcrossActiveJobs` respecting `ScheduledAt`; a frozen target becomes deferred instead of dispatching; a deferred target resumes once its freeze row's `to_at` passes).
- **API handlers**: schedule/freeze CRUD tests reusing Sub-project 6/4's `mustExecAPI`/`withURLParam`/`auth.ContextWithClaims` patterns; RBAC matrix rows for all 5 new routes plus the modified `batch-remediation` route (unchanged permission, still needs its existing row's behavior reverified).

## 9. Explicitly deferred

Everything in §2's "out of scope" list is deferred, not cut — `Schedule.Payload` being free-form `jsonb` already supports future job types beyond `batch_remediation` without a schema change, and `AgentFreeze` has no structural blocker to adding recurrence later if real usage demands it.
