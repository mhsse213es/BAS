# Continuous BAS Revalidation (Phase 5) — Design

## 1. Problem statement

Sub-project 5 proved a control actually stops a real attack at the moment `VerifyTechnique` is manually triggered — but drift is a fact of endpoint life: a GPO gets reverted, a config drifts back, an update silently disables a hardening setting. A one-time PASS says nothing about whether the control is still effective a week later. Phase 5 closes that gap: an opt-in per-remediation flag that automatically re-runs the same technique verification at T+24h, T+7d, and T+30d after the remediation completes, with zero manual re-triggering.

## 2. Scope

**In scope:**
- `remediation_requests.continuous_validation` — opt-in boolean, set at request-creation time on all three creation paths (single-endpoint, batch, recurring-schedule).
- A new `Job.Type = "bas_revalidation"` — three one-shot singleton-target Jobs created together the moment a continuous-validation-enabled remediation's fix verification PASSes, scheduled via the existing `Job.ScheduledAt` primitive (Sub-project 7) at now+24h/+7d/+30d.
- Type-switching dispatch/status registration in `internal/api` so `internal/jobs.Dispatcher` can drive more than one job type without any change to `internal/jobs` itself.
- Reuse of the existing `dispatchTechniqueVerification` mechanism and `technique_verification_runs` table — no new dispatch mechanics, no new verification taxonomy.
- Cancellation of any still-pending revalidation jobs for a request when that request is rolled back.
- One new read endpoint to view a request's revalidation chain.

**Explicitly out of scope, deferred:**
- Automatic/mandatory revalidation for every remediation — this is opt-in only (explicit, non-default choice).
- Configurable interval sets — fixed 24h/7d/30d chain for V1; no per-remediation custom schedule.
- Drift *history* / trend view across many revalidation cycles beyond the 3-Job chain (Phase 6, depends on this).
- Notifications on revalidation PASS/FAIL (Phase 7).
- Any frontend/UI — backend/API only, consistent with every prior sub-project in this initiative.
- Re-triggering `VerifyTechnique`'s own one-shot uniqueness guard, or changing it in any way — the new path bypasses it entirely by design (see §3).

## 3. Architecture

`internal/jobs` needs zero changes for this sub-project — Sub-project 6 already parameterized `DispatchFn`/`StatusFn` by `Job`/`jobType` in anticipation of exactly this. The only new `internal/jobs`-adjacent code lives in `internal/api`: a pair of type-switching functions, `dispatchJobTarget`/`statusForJobTarget`, that branch on `job.Type` and delegate to either Sub-project 6's existing `dispatchBatchRemediationTarget`/`batchRemediationTargetStatus` (unchanged) or a new `dispatchBasRevalidationTarget`/`basRevalidationTargetStatus` pair. `WithJobsDispatcher` registers the two switches instead of the batch-remediation functions directly — behavior-neutral for every existing `batch_remediation` job.

The trigger point is `handleRemediationVerifyResult` (`internal/api/remediation_continuation.go`), which already runs the instant a fix's verification check PASSes. When `status == StatusCompleted` AND the request's `continuous_validation` flag is true AND `EligibleForBASVerification(checkID)` (Sub-project 5's existing technique_id gate — never invents a mapping for a check with no honest ATT&CK fit), it creates three `bas_revalidation` Jobs in one shot via `CreateBatchScheduled`, each a singleton-target job (`AgentIDs = []string{agentID}`) since a revalidation is inherently one endpoint re-checking one control, `ScheduledAt` set to completion-time +24h/+7d/+30d respectively.

`dispatchBasRevalidationTarget` is genuinely just `VerifyTechnique`'s dispatch body extracted and reused: it inserts a `technique_verification_runs` row, calls the unchanged `dispatchTechniqueVerification`, and updates the row to `dispatched`/`error`. Because it writes `run_id` onto `technique_verification_runs` exactly as `VerifyTechnique` already does, Sub-project 5's existing `continueRemediationFromResult` continuation hook (its final `technique_verification_runs WHERE run_id = $1 AND status = 'dispatched'` branch) picks up the eventual scenario result automatically — **no new continuation-hook code is needed at all**. `VerifyTechnique`'s per-`request_id` uniqueness guard (`SELECT EXISTS(...) WHERE request_id=$1`) lives entirely inside `VerifyTechnique`'s own handler body, not the schema (confirmed: no unique index on `technique_verification_runs.request_id`), so the new automated path simply never calls it and multiple rows accumulate per request over the three revalidation cycles exactly as intended.

On rollback confirmation (`handleRemediationRollbackVerifyResult`, the `!passed` / `status == "completed"` branch — meaning the check now fails again, confirming the control actually reverted), any still-pending `bas_revalidation` jobs for that `requestId` are cancelled via the existing `h.jobsStore.CancelJob`, found by querying `jobs WHERE type='bas_revalidation' AND payload->>'requestId'=$1 AND state NOT IN (terminal states)`. Revalidating a control that was just deliberately reverted would be actively misleading, not merely wasteful.

## 4. Data model

```go
// internal/api/job_dispatch.go — existing struct, gains one field
type batchRemediationPayload struct {
    RemediationID        string `json:"remediationId"`
    Reason               string `json:"reason"`
    ContinuousValidation bool   `json:"continuousValidation"`
}

// internal/api/bas_revalidation_dispatch.go (new file)
// basRevalidationPayload is the Job.Payload shape for Type="bas_revalidation".
// Self-contained -- no re-lookup of remediation_requests needed at dispatch time.
type basRevalidationPayload struct {
    RequestID   string `json:"requestId"`
    AgentID     string `json:"agentId"`
    CheckID     string `json:"checkId"`
    TechniqueID string `json:"techniqueId"`
}
```

```sql
ALTER TABLE remediation_requests ADD COLUMN IF NOT EXISTS continuous_validation boolean NOT NULL DEFAULT false;
```

No new table. `bas_revalidation` Jobs live in the existing `jobs`/`job_targets` tables from Sub-project 6; their per-target verification detail lives in the existing `technique_verification_runs` table from Sub-project 5. `jobs.payload` is already `jsonb` (confirmed), so `payload->>'requestId'` filtering for the rollback-cancellation query works with no schema change.

**Threading `continuous_validation` through all three creation paths:**
1. `ExecuteRemediation` (`internal/api/remediation_handlers.go`) — its inline request struct gains `ContinuousValidation bool \`json:"continuousValidation"\``, written directly into the existing `INSERT INTO remediation_requests (...)`.
2. `CreateBatchRemediationJob` (`internal/api/job_handlers.go`) — its inline request struct gains the same field; the payload marshal changes from an inline `map[string]string{"remediationId":..., "reason":...}` to marshaling `batchRemediationPayload{RemediationID: entry.ID, Reason: req.Reason, ContinuousValidation: req.ContinuousValidation}` directly. `dispatchBatchRemediationTarget`'s two `INSERT INTO remediation_requests` branches (the already-compliant `completed_at` branch and the normal dispatch branch) both gain `continuous_validation` as a bound column, read from the unmarshaled payload.
3. `CreateJobSchedule` (`internal/api/schedule_handlers.go`) — same treatment: request struct gains the field, and its payload marshal switches from the inline map to `batchRemediationPayload{...}`. No `job_schedules` schema change — the flag rides inside the same `payload` jsonb column already stored per schedule, and `spawnDueSchedules` (Sub-project 7) replays that exact payload unmodified into every spawned Job, so every occurrence of a recurring remediation inherits the flag automatically.

## 5. Dispatch-loop mechanics

```go
// internal/api/job_dispatch.go — WithJobsDispatcher changes registration target
func (h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler {
    h.jobsStore = store
    dispatcher.SetDispatch(h.dispatchJobTarget) // was: h.dispatchBatchRemediationTarget
    dispatcher.SetStatus(h.statusForJobTarget)  // was: h.batchRemediationTargetStatus
    return h
}

func (h *Handler) dispatchJobTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
    switch job.Type {
    case "batch_remediation":
        return h.dispatchBatchRemediationTarget(ctx, job, target)
    case "bas_revalidation":
        return h.dispatchBasRevalidationTarget(ctx, job, target)
    default:
        return "", fmt.Errorf("unknown job type %q", job.Type)
    }
}

func (h *Handler) statusForJobTarget(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
    switch jobType {
    case "batch_remediation":
        return h.batchRemediationTargetStatus(ctx, jobType, refID)
    case "bas_revalidation":
        return h.basRevalidationTargetStatus(ctx, jobType, refID)
    default:
        return jobs.TargetStateFailed, "unknown job type", true
    }
}
```

```go
// internal/api/bas_revalidation_dispatch.go
func (h *Handler) dispatchBasRevalidationTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
    var payload basRevalidationPayload
    if err := json.Unmarshal(job.Payload, &payload); err != nil {
        return "", err
    }
    techVerifyID := newID()
    if _, err := h.db.Exec(ctx,
        `INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
         VALUES ($1,$2,$3,$4,$5,'requested',$6)`,
        techVerifyID, payload.RequestID, target.AgentID, payload.CheckID, payload.TechniqueID, job.CreatedBy,
    ); err != nil {
        return "", err
    }

    runID, sent, err := h.dispatchTechniqueVerification(ctx, target.AgentID, payload.TechniqueID)
    if err != nil {
        h.db.Exec(ctx, `UPDATE technique_verification_runs SET status='error', reason=$1 WHERE id=$2`, err.Error(), techVerifyID)
        return "", err
    }
    if !sent {
        h.db.Exec(ctx, `UPDATE technique_verification_runs SET status='error', reason='agent not connected' WHERE id=$1`, techVerifyID)
        return "", errors.New("agent not connected")
    }
    h.db.Exec(ctx,
        `UPDATE technique_verification_runs SET status='dispatched', run_id=$1, dispatched_at=NOW() WHERE id=$2`,
        runID, techVerifyID)
    return techVerifyID, nil
}

// basRevalidationTargetStatus polls the technique_verification_runs row
// (refID = its own id, not run_id) written by dispatchBasRevalidationTarget
// above. Only models.ResultPass counts as job-target success -- fail/error/
// blocked/skipped are all terminal-but-failed, reusing Sub-project 5's
// existing 5-value taxonomy without adding a 6th.
func (h *Handler) basRevalidationTargetStatus(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
    var status, reason string
    if err := h.db.QueryRow(ctx, `SELECT status, reason FROM technique_verification_runs WHERE id=$1`, refID).Scan(&status, &reason); err != nil {
        return jobs.TargetStateFailed, "technique verification run not found: " + err.Error(), true
    }
    switch status {
    case string(models.ResultPass):
        return jobs.TargetStateCompleted, "", true
    case string(models.ResultFail), string(models.ResultError), string(models.ResultBlocked), string(models.ResultSkipped):
        return jobs.TargetStateFailed, reason, true
    default: // "requested", "dispatched"
        return jobs.TargetStateDispatched, "", false
    }
}
```

**Trigger** (`handleRemediationVerifyResult`, on the PASS branch only):

```go
if passed {
    var continuousValidation bool
    var checkID string
    h.db.QueryRow(ctx, `SELECT check_id, continuous_validation FROM remediation_requests WHERE id=$1`, requestID).
        Scan(&checkID, &continuousValidation)
    if continuousValidation && h.EligibleForBASVerification(checkID) {
        step, _ := h.findStepByCheckID(checkID)
        payload, _ := json.Marshal(basRevalidationPayload{
            RequestID: requestID, AgentID: agentID, CheckID: checkID, TechniqueID: step.TechniqueID,
        })
        now := time.Now().UTC()
        for _, delay := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour} {
            at := now.Add(delay)
            h.jobsStore.CreateBatchScheduled(ctx, "bas_revalidation", payload, requestedBy, []string{agentID}, &at)
        }
    }
}
```

**Rollback-cancellation** (`handleRemediationRollbackVerifyResult`, the `status == "completed"` branch — rollback confirmed reverted):

```go
rows, _ := h.db.Query(ctx,
    `SELECT id FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'=$1
     AND state NOT IN ('completed','partial','failed','cancelled')`, requestID)
defer rows.Close()
for rows.Next() {
    var jobID string
    rows.Scan(&jobID)
    h.jobsStore.CancelJob(ctx, jobID)
}
```

## 6. API surface

- `POST /api/agents/{agentId}/remediations` (`ExecuteRemediation`) — gains optional `continuousValidation bool` (default `false`). No permission change.
- `POST /api/jobs/batch-remediation` (`CreateBatchRemediationJob`) — same field, same no-permission-change reasoning.
- `POST /api/job-schedules` (`CreateJobSchedule`) — same field; every spawned occurrence inherits it via the stored payload.
- **New:** `GET /api/remediation-requests/{requestId}/revalidations` — lists every `bas_revalidation` job tied to `requestId` (`jobs WHERE type='bas_revalidation' AND payload->>'requestId'=$1 ORDER BY scheduled_at`), each row paired with its single target's `ref_id` → `technique_verification_runs.status`/`reason`. Lets an operator see "24h: pass, 7d: pending, 30d: not yet scheduled" for one remediation. RBAC: `auth.CanExecuteRemediation` (read-level, matches `GetJob`'s precedent) — no new permission.
- `GET /api/jobs/{jobId}` — unchanged; already type-agnostic since Sub-project 6.

## 7. Error handling

- **Agent not connected at a scheduled revalidation's dispatch time** — `dispatchBasRevalidationTarget` returns an error, the target (and therefore that one revalidation Job, since it's a singleton) ends `failed`; the other two Jobs in the chain (already created independently) are unaffected and still fire on their own schedule.
- **Check no longer eligible at trigger time** (e.g. `findStepByCheckID` can't find the step — scenario catalog changed between the original fix and now) — `EligibleForBASVerification` returns `false`, no revalidation chain is created; this mirrors `VerifyTechnique`'s own existing 422 behavior for the manual path, just silent (no HTTP caller to respond to) instead of an error response.
- **Remediation rolled back before a scheduled revalidation fires** — covered by §3/§5's cancellation step; `CancelJob` only touches non-terminal targets, so a revalidation that already dispatched and is mid-flight when the rollback lands is left to finish (matches `CancelJob`'s existing Sub-project 6 semantics for every other job type — no special case).
- **Duplicate technique_verification_runs rows per request** — expected and required by design (three rows accumulate over 24h/7d/30d), not an error; `techniqueVerificationFindings` (Sub-project 5) already queries `DISTINCT ON (check_id) ... ORDER BY check_id, completed_at DESC`, so the endpoint risk view always reflects the *latest* revalidation result, automatically superseding older ones.

## 8. Testing

- **`dispatchBasRevalidationTarget`**: DB-backed tests mirroring `dispatchBatchRemediationTarget`'s existing test shape — success path (row ends `dispatched` with `run_id` set), agent-not-connected path (row ends `error`), dispatch error path.
- **`basRevalidationTargetStatus`**: table-driven over all five `models.CheckResult` values plus `requested`/`dispatched`, verifying the pass/fail/non-terminal split in §5.
- **Trigger logic**: extend `handleRemediationVerifyResult`'s existing test coverage with `continuous_validation=true` + eligible check → asserts exactly 3 `bas_revalidation` jobs created with `ScheduledAt` at the correct offsets; `continuous_validation=false` → asserts zero; `continuous_validation=true` + ineligible check (no technique_id) → asserts zero.
- **Rollback cancellation**: seed a `bas_revalidation` job in `requested` state tied to a request, trigger `handleRemediationRollbackVerifyResult`'s completed branch, assert the job's state is `cancelled`.
- **Type-switching dispatch**: a table-driven test over `dispatchJobTarget`/`statusForJobTarget` confirming `batch_remediation` and `bas_revalidation` route to their respective functions, and an unknown type returns the `default` error branch.
- **`GET /api/remediation-requests/{requestId}/revalidations`**: handler test asserting it returns all 3 chain jobs with correct per-job state, RBAC matrix row for the new route.
- Reuse the `.Truncate(time.Microsecond)` timestamptz-precision fix (Sub-project 7 gotcha) for any test asserting `ScheduledAt` equality against a DB round-trip.

## 9. Explicitly deferred

Everything in §2's "out of scope" list is deferred, not cut. In particular: automatic revalidation for all remediations (vs. opt-in) and configurable interval sets are both real product directions the opt-in flag and fixed 3-Job chain leave room for later — `basRevalidationPayload` and the `bas_revalidation` job type need no structural change to support either. Drift *history* (Phase 6) consumes exactly this sub-project's output (the accumulating `technique_verification_runs` rows) and is the natural next sub-project once this one ships.
