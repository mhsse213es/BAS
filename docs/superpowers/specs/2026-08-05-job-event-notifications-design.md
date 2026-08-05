# Job-Event Notifications (Phase 7) — Design

**Date:** 2026-08-05
**Status:** Approved, ready for implementation plan
**Sub-project:** 11th sub-project of the Endpoint Health & Remediation initiative — original Phase 7 of the 10-phase Fleet Job Engine proposal (Sub-project 6), the first of the three still-deferred original phases (7 Notifications, 8 Ownership, 9 SLA — SLA depends on both 7 and 8).

## Problem

The Fleet Job Engine (Sub-projects 6-10) gives an operator everything they need to *poll for* a job's status — `GetJob` returns targets and, since Sub-project 10, a computed `progress` summary. But nothing *pushes*. An operator running a 2,000-endpoint remediation batch has no way to learn that 150 targets failed on a permissions error except by repeatedly polling and diffing. Phase 7 closes that gap: the Job Engine emits notifications for the events an operator actually needs to act on, delivered live (in-app) and to an external channel (webhook) they already monitor.

## Scope

**In scope:** job-level lifecycle events, target-level exception events, in-app (WebSocket) delivery, webhook delivery, a persisted flat history, read + config API surface.

**Out of scope (explicitly deferred):** email delivery (SMTP — noted as a future channel, not built now), read/unread tracking, per-notification delivery-status/retry tracking, notification preferences per-user, any UI beyond what already exists to receive the new WS message type. None of these are assumed or half-built — they're clean additions later if needed.

## Event Model

New sibling package `internal/notifications` (DB-backed, unlike the pure-compute `internal/driftanalytics`/`internal/jobs/progress.go` packages, since these events must persist).

```go
package notifications

type EventType string

const (
    EventJobStarted   EventType = "job_started"             // Requested -> Running
    EventJobCompleted EventType = "job_completed"            // all targets completed
    EventJobPartial   EventType = "job_partially_completed"  // mixed completed/failed
    EventJobFailed    EventType = "job_failed"                // all targets failed
    EventJobCancelled EventType = "job_cancelled"             // operator cancel action

    EventTargetFailed   EventType = "target_failed"
    EventTargetDeferred EventType = "target_deferred"
)

type Severity string

const (
    SeverityInfo     Severity = "info"
    SeverityWarning  Severity = "warning"
    SeverityError    Severity = "error"
    SeverityCritical Severity = "critical"
)

type Event struct {
    Type      EventType
    JobID     string
    TargetID  string         // "" for job-level events
    AgentID   string         // "" for job-level events
    Severity  Severity
    Message   string
    Metadata  map[string]any // e.g. {"cancelledCount": 12} on EventJobCancelled
    Timestamp time.Time
}
```

**Severity mapping:**

| Event | Severity |
|---|---|
| `EventJobStarted` | Info |
| `EventJobCompleted` | Info |
| `EventJobPartial` | Warning |
| `EventTargetDeferred` | Warning |
| `EventJobCancelled` | Warning |
| `EventTargetFailed` | Error |
| `EventJobFailed` | Critical |

**No `TargetCancelled` event type.** Grounding against `internal/jobs/store.go`'s `CancelJob` shows `TargetStateCancelled` is produced *only* by that function's bulk `UPDATE job_targets ... WHERE state='pending'` — no `StatusFn` implementation anywhere ever returns it, so there is no scenario where a single dispatched target transitions to Cancelled independently of a whole-job cancel. A separate per-target event would just double-count the one `EventJobCancelled` action; the cancelled count instead lives in `EventJobCancelled.Metadata["cancelledCount"]`.

**No `TargetTimedOut` event type.** `internal/jobs/types.go` defines exactly `pending/dispatched/completed/failed/cancelled/deferred` for `TargetState*` — no timeout state exists in this codebase today.

**`EventJobStarted` is in scope** (not deferred) because `Dispatcher.Tick()` already re-checks `newState != job.State` for every transition, not just terminal ones (see Emission Hooks below) — catching Requested→Running costs one extra branch, not a new mechanism.

**Normal lifecycle events generate no notification**: `TargetStatePending`, `TargetStateDispatched`, `TargetStateCompleted` (individually — the job reaching all-completed *does* emit `EventJobCompleted`), and the ordinary Requested→Running→Completed job progression beyond the Started/terminal boundary. These stay visible only through `ComputeProgress` (Sub-project 10), avoiding the "2,000-target event firehose" the original brainstorm called out.

## Persistence

```sql
CREATE TABLE notifications (
    id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    type       text        NOT NULL,
    job_id     text        NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    target_id  text        NOT NULL DEFAULT '',
    agent_id   text        NOT NULL DEFAULT '',
    severity   text        NOT NULL,
    message    text        NOT NULL,
    metadata   jsonb       NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notifications_created_at ON notifications (created_at DESC);
CREATE INDEX idx_notifications_job_id ON notifications (job_id);
```

A flat, append-only event log — no read/unread flag, no per-channel delivery-status columns, no retry queue. These are real future needs (an inbox UI wants read/unread; a flaky webhook wants retry) but nothing in this design depends on them yet, and adding the columns later is a pure additive migration.

```sql
CREATE TABLE notification_webhooks (
    id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name         text        NOT NULL,
    url          text        NOT NULL,
    secret       text        NOT NULL DEFAULT '',
    min_severity text        NOT NULL DEFAULT 'warning',
    enabled      boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT NOW()
);
```

Trimmed from `ticketing_configs`' shape (`internal/db/postgres.go:793`) — no `provider` column, since a notification webhook is always a generic POST (Slack/Teams/OpsGenie/custom SOAR all consume the same JSON+HMAC shape, same reasoning as `ticketing.webhookConnector`'s doc comment).

## Emission Hooks

`Dispatcher` (`internal/jobs/dispatch.go`) gains a third injected callback, mirroring the existing `DispatchFn`/`StatusFn` pattern used specifically to keep `internal/jobs` free of any `internal/api` import. Unlike `DispatchFn`/`StatusFn` — which every real call site always sets before calling `Tick()` — `NotifyFn` is optional: every existing test in `dispatch_test.go`, and every existing `Handler` constructed in `job_handlers_test.go` without `.WithNotifications(...)`, never sets it. Every call to `d.notify` must therefore be guarded with `if d.notify != nil`, and `internal/api`'s equivalent call to `h.notifications.Emit` must be guarded with `if h.notifications != nil` — the same "nil when not loaded" convention already used for every other optional `Handler` field (`remediationCatalog`, `jobsStore`, etc.). Skipping either guard would panic every pre-existing test that doesn't wire notifications.

```go
// NotifyEvent is internal/jobs's own copy of the event shape -- internal/jobs
// must not import internal/notifications (same reason it never imports
// internal/api: DispatchFn/StatusFn/NotifyFn are all injected specifically
// to keep this package a leaf dependency).
type NotifyEvent struct {
    Type     string // one of the EventJob*/EventTarget* string values, duplicated as untyped
    JobID    string
    TargetID string
    AgentID  string
    Severity string
    Message  string
    Metadata map[string]any
}

type NotifyFn func(ctx context.Context, evt NotifyEvent)

func (d *Dispatcher) SetNotify(fn NotifyFn) { d.notify = fn }
```

`internal/jobs.NotifyEvent` is a plain-string mirror of `notifications.Event` (no shared import). `internal/api`'s `dispatchJobNotify(evt jobs.NotifyEvent)` — the function passed to `SetNotify` in `WithJobsDispatcher` — is the sole place that converts `jobs.NotifyEvent` into a typed `notifications.Event` and calls `h.notifications.Emit`. This mirrors the existing `DispatchFn`/`StatusFn` boundary exactly: `internal/jobs` defines the callback shape in its own vocabulary, `internal/api` is where the two domains meet.

`NotifyEvent.Type`/`.Severity` are plain strings, not the `notifications.EventType`/`Severity` typed constants — `internal/jobs` can't reference a package it doesn't import. It uses its own local string constants for the values it emits, matching `notifications`' string values by convention (documented, not type-checked) — the same shape already used at the `internal/jobs` ↔ `internal/api` boundary for `Job.Type` (`"batch_remediation"`/`"bas_revalidation"` are bare strings `dispatchJobTarget`/`statusForJobTarget` switch on, not a shared enum either).

```go
// internal/jobs's own spelling of the event-type/severity strings it emits.
// Must match notifications.EventType / notifications.Severity's string
// values exactly -- internal/api's dispatchJobNotify is what connects them.
const (
    notifyTypeJobStarted    = "job_started"
    notifyTypeJobCompleted  = "job_completed"
    notifyTypeJobPartial    = "job_partially_completed"
    notifyTypeJobFailed     = "job_failed"
    notifyTypeTargetFailed  = "target_failed"
    notifyTypeTargetDeferred = "target_deferred"

    notifySeverityInfo     = "info"
    notifySeverityWarning  = "warning"
    notifySeverityError    = "error"
    notifySeverityCritical = "critical"
)
```

Called from the 3 existing mutation points in `Tick()`, with zero change to their surrounding logic:

`TargetStateFailed` is set from **two** distinct call sites in `Tick()`, both need the same emission:

1. **`internal/jobs/dispatch.go:73`** — `MarkTargetTerminal(ctx, t.ID, state, errText)` inside the in-flight-resolution loop (a dispatched target's `StatusFn` polling resolves to failed). If `state == TargetStateFailed`, call `d.notify(ctx, NotifyEvent{Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID, Severity: notifySeverityError, Message: errText})`. No event for `TargetStateCompleted`.
1b. **`internal/jobs/dispatch.go:110`** — `MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())` inside the pending-targets loop, when `d.dispatch(...)` itself returns an error (e.g. agent offline — the exact scenario `TestTick_DispatchErrorMarksTargetFailedWithoutAborting` already covers). Same `EventTargetFailed` emission, `Message: dispatchErr.Error()`.
2. **`internal/jobs/dispatch.go:104`** — `MarkTargetDeferred(ctx, t.ID, reason)` inside the same pending-targets loop, when a pending target discovers its agent is now frozen. Always emits `notifyTypeTargetDeferred`, `notifySeverityWarning`, `Message: reason`. (The separate un-freeze loop at lines 83-92, which moves a target back from Deferred to Pending, emits nothing — resuming normal dispatch isn't an exception.)
3. **`internal/jobs/dispatch.go:128`** — `SetJobState(ctx, jobID, newState)` inside the touched-jobs loop, guarded by the existing `if newState != job.State`. Classify via a new pure function:

```go
// classifyJobTransition maps a Job's new aggregate state to the notification
// event it produces, or ok=false if this transition isn't notification-worthy.
func classifyJobTransition(newState string) (eventType, severity string, ok bool) {
    switch newState {
    case JobStateRunning:
        return notifyTypeJobStarted, notifySeverityInfo, true
    case JobStateCompleted:
        return notifyTypeJobCompleted, notifySeverityInfo, true
    case JobStatePartial:
        return notifyTypeJobPartial, notifySeverityWarning, true
    case JobStateFailed:
        return notifyTypeJobFailed, notifySeverityCritical, true
    default:
        return "", "", false // JobStateRequested, JobStateCancelled (handled separately)
    }
}
```

`JobStateCancelled` is deliberately excluded here — `AggregateState` never *returns* `JobStateCancelled` (line 9-11 of `state.go` short-circuits before computing anything once a job is already cancelled), so this branch is dead for that state anyway. `EventJobCancelled` is emitted from `CancelJob`'s call site instead (below), which is the only place that state is ever set.

4. **`internal/api/job_handlers.go`'s `CancelJob` handler** — `Store.CancelJob` is a direct bulk SQL statement, never routed through `Tick()`. Immediately after the existing `cancelledCount, err := h.jobsStore.CancelJob(r.Context(), jobID)` call (and alongside the existing `h.auditLog(...)` call), emit:

```go
h.notifications.Emit(r.Context(), notifications.Event{
    Type: notifications.EventJobCancelled, JobID: jobID, Severity: notifications.SeverityWarning,
    Message: "job cancelled", Metadata: map[string]any{"cancelledCount": cancelledCount},
})
```

`WithJobsDispatcher` (`internal/api/job_dispatch.go:131-136`) gains one line: `dispatcher.SetNotify(h.dispatchJobNotify)`, where `dispatchJobNotify` adapts a `jobs.Event` to `notifications.Event` and calls `h.notifications.Emit`.

## Delivery

`notifications.Service.Emit(ctx, evt Event)`:

1. **Persist** — `INSERT INTO notifications`. Logged on failure; delivery is still attempted (a notification that failed to store is still worth pushing live).
2. **WS push** — `broadcaster.BroadcastBrowsers(models.WSMessage{Type: "notification", Payload: evt})`. `Service` is constructed with a `Broadcaster` interface (`BroadcastBrowsers(models.WSMessage)`), not a concrete `*ws.Hub` — same decoupling reason `integrity.TamperBroadcaster` already exists for the tamper-alert path (`internal/ws/hub.go:149-161`).
3. **Webhook fan-out** — for every `notification_webhooks` row with `enabled=true` and `min_severity` at-or-below `evt.Severity` (ordering `info(0) < warning(1) < error(2) < critical(3)`), POST the event as JSON with an `X-BAS-Signature` HMAC-SHA256 header when `secret` is set. Fired via `go func(){...}()`, matching `internal/api/audit.go`'s `auditLogAs` fire-and-forget pattern — a slow or broken external webhook must never block `Dispatcher.Tick()` or an HTTP handler.

The POST+HMAC sender (~20 lines) is a **new, standalone implementation** in `internal/notifications`, not shared with `ticketing.webhookConnector` (`internal/ticketing/webhook.go`) — that type is unexported and shaped around the ITSM `Connector` interface (`CreateTicket`/`AddComment`/`CloseTicket`/etc.). Notifications and ticketing are different domains that happen to both POST JSON with HMAC signing; duplicating ~20 lines is cheaper and clearer than coupling them through a shared package for this.

## API Surface & RBAC

Following this initiative's established split: read/act = Analyst+Admin via `CanExecuteRemediation`; anything credential-shaped = Admin-only via `CanApproveRemediation` (same rationale as maintenance-freeze create/delete — a webhook secret, like a freeze, can silently affect the whole fleet).

- **`GET /api/notifications`** — paginated (`limit` default 100 max 500, `offset`), most-recent-first, optional `jobId`/`severity`/`type` filters. Mirrors `GetAuditLogs`'s existing param handling (`internal/api/audit.go:60-67`). `CanExecuteRemediation`.
- **`POST /api/notification-webhooks`** — create. `CanApproveRemediation`.
- **`GET /api/notification-webhooks`** — list (secret redacted, mirroring `ticketing.Config.MaskedConfig()`'s `***` masking for sensitive settings). `CanApproveRemediation`.
- **`DELETE /api/notification-webhooks/{id}`** — `CanApproveRemediation`.

No update endpoint — delete-and-recreate, matching this codebase's preference for small surfaces absent evidence of an edit-in-place need.

No new WS route: `notification` messages ride the existing `ServeBrowserWS` connection every dashboard session already holds open (`internal/ws/hub.go:82`).

## Testing

- **`classifyJobTransition`** — pure function, unit-tested exhaustively against all `JobState*` constants including the dead `JobStateCancelled`/`JobStateRequested` cases (table-driven, no container).
- **`notifications.Service.Emit`** — container-backed: row lands correctly in `notifications`; a fake `Broadcaster` records the `BroadcastBrowsers` call; a fake `httptest.Server` captures the webhook POST body + `X-BAS-Signature` header and confirms `min_severity` filtering excludes/includes correctly.
- **`Dispatcher.Tick()` integration** — extend `internal/jobs/dispatch_test.go` with a fake `NotifyFn` capturing emitted events; assert a target-failure tick emits exactly one `EventTargetFailed`, and that the job reaching `JobStateFailed`/`JobStatePartial`/`JobStateCompleted` emits exactly the matching job-level event.
- **`CancelJob` handler** — extend `internal/api/job_handlers_test.go` asserting `EventJobCancelled` fires with the correct `cancelledCount` in `Metadata`.
- **RBAC matrix** — 2 new rows in `internal/api/rbac_matrix_test.go`: `GET /api/notifications` (`CanExecuteRemediation`), `notification-webhooks` CRUD (`CanApproveRemediation`).

## Dependencies

Builds directly on Sub-project 6's `Dispatcher`/`Store` (`internal/jobs`), Sub-project 7's `TargetStateDeferred` (`internal/jobs/dispatch.go:83-92`), and the existing `ws.Hub`/`integrity.TamperBroadcaster` precedent (`internal/ws/hub.go`). No dependency on Sub-projects 8-10 (continuous revalidation, drift analytics, progress tracking) beyond them already having proven the `internal/jobs` extension pattern is stable.
