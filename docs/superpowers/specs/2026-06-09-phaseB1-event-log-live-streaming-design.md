# Phase B-1 — Event-Sourced Run Log + Live Streaming — Design

**Status:** approved design (brainstormed 2026-06-09), ready for an implementation plan.
**Parent:** `2026-06-09-fast-accurate-simulation-engine-design.md` §5 (Phase B). This spec scopes **B-1 only**: the event-sourced execution log and live run streaming. The versioned batched-dispatch / on-demand-payload-by-hash protocol (§5.1) is deferred to a later sub-project (B-2), to be picked up when Phase C content scale makes single-message dispatch a real bottleneck.

---

## 1. Goal

Give the server and UI a **live, persisted view of a run as it executes**, and make a run **reconstructable after a crash or cancel** — without touching scoring, reporting, or the dispatch path.

Today the agent runs the whole scenario locally and POSTs the full results array once to `/api/scenarios/result`. The server is blind during the run (`scenario_runs.results` is written once at the end; `UpdateProgress` only updates the agent's *local* status API). A crash mid-run loses everything except what the truncated run's final POST happens to carry. Phase A made runs fast and concurrent — but an operator watching one still sees nothing until it finishes, and can't tell a busy parallel run from a stalled one.

## 2. Scope

**In scope**
- An append-only **run-event stream** (lifecycle events only — no stdout chunks) emitted by the agent, persisted by the server, relayed live to browsers.
- A **denormalized progress summary** on `scenario_runs` (total / done / passed / failed / timed-out / currently-running) for cheap list + detail rendering.
- **Capability negotiation** so legacy agents keep working unchanged.
- A **live run-detail UI** driven by the stream, falling back to final results on completion.

**Out of scope** (explicitly)
- `StepOutputChunk` / live per-step stdout streaming. Discovery steps finish in well under a second; streaming partial output is high-volume for little value. Full stdout still arrives in the authoritative final POST.
- Versioned **batched dispatch** and **on-demand payload-by-hash** delivery (B-2).
- Any change to scoring, reporting, the snapshot/revert flow, or the resource/timeout scheduler.

## 3. Authoritative model (the one rule that keeps this simple)

- **The final `/api/scenarios/result` POST is authoritative.** It still writes `scenario_runs.results` + `score` exactly as today.
- **The event stream is best-effort live progress + resilience.** When the final POST arrives, **its results win, always** — no merging, no conflict resolution, no attempt to "correct" the POST using events. If the event stream dropped events, the POST still delivers correct results.

This is the design's load-bearing simplification: events never have to be complete or perfectly ordered to be useful, because they are never the source of truth.

## 4. Event model

A `RunEvent` (agent → server):

```json
{
  "runId": "5f3c…",
  "seq": 123,                  // per-run monotonic counter assigned by the agent
  "type": "completed",         // see types below
  "taskId": "a1b2c3d4",        // empty for run-level events
  "techniqueId": "T1057",      // empty for run-level events
  "ts": "2026-06-09T16:40:12.512Z",
  "payload": { "verdict": "pass", "durationMs": 532, "exitCode": 0 }
}
```

**Event types**

| type | level | payload |
|------|-------|---------|
| `run_started` | run | `{ "stepsTotal": 265, "mode": "telemetry" }` |
| `queued` | step | `{}` |
| `started` | step | `{}` |
| `completed` | step | `{ "verdict": "pass\|fail\|blocked", "durationMs": N, "exitCode": N }` |
| `timeout` | step | `{ "reason": "execute\|schedule", "durationMs": N }` |
| `killed` | step | `{ "reason": "cancelled", "durationMs": N }` |
| `run_completed` | run | `{ "stepsDone": N, "partial": false }` |
| `run_cancelled` | run | `{ "stepsDone": N }` |

`seq` is a single per-run counter (atomic), incremented for every event the agent emits (run-level and step-level alike), so the server can order and de-duplicate purely by `(runId, seq)` regardless of arrival order. Run-level boundary events (`run_started` / `run_completed` / `run_cancelled`) make run state explicit so the server never has to *infer* run lifecycle from step events, and make timeline rendering and later analytics straightforward.

Note: `payload` carries the verdict/duration/exit/reason — there is **no separate `verdict` column**. Keeping a single opaque `payload jsonb` makes schema evolution painless (new fields never require a migration).

**`workerId` is deliberately excluded from B-1.** Its value is purely diagnostic (host-pool / worker-starvation / timeout-clustering analysis), which none of B-1's goals — live progress, crash resilience, timeline visibility — require. Including it would force the scheduler → Job model → event model → tests to all become aware of worker assignment, violating the spec's core boundary: *the event layer observes execution, it does not influence it.* When that diagnostic need arises, `workerId` is added **inside `payload`** with **zero schema change** (the column stays out of the table). See §13.

## 5. Persistence

**New table `run_events`** (schema-light, append-only):

```sql
CREATE TABLE IF NOT EXISTS run_events (
    run_id       text        NOT NULL,
    seq          bigint      NOT NULL,
    type         text        NOT NULL,
    task_id      text        NOT NULL DEFAULT '',
    technique_id text        NOT NULL DEFAULT '',
    ts           timestamptz NOT NULL,
    payload      jsonb       NOT NULL DEFAULT '{}',
    PRIMARY KEY (run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_run_events_run ON run_events(run_id, seq);
```

Ordering is **always** by `(run_id, seq)`, never by arrival/insert time.

**Denormalized progress summary on `scenario_runs`** (added columns, all default 0):

```sql
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_total   int NOT NULL DEFAULT 0;
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_done    int NOT NULL DEFAULT 0;
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_running int NOT NULL DEFAULT 0;
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_passed  int NOT NULL DEFAULT 0;
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_failed  int NOT NULL DEFAULT 0;
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_timeout int NOT NULL DEFAULT 0;
```

These let a list view render "147/265 · 12 failed · 8 running" without scanning `run_events`. They are an overlay; the authoritative final results remain in `scenario_runs.results`.

### 5.1 Idempotent summary updates (the most important correctness rule)

Counter updates are tied to a **successful insert**, never applied blindly — so a network retry that redelivers `seq=42` cannot double-count:

```sql
WITH ins AS (
    INSERT INTO run_events (run_id, seq, type, task_id, technique_id, ts, payload)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    ON CONFLICT (run_id, seq) DO NOTHING
    RETURNING type, payload
)
UPDATE scenario_runs s SET
    steps_total   = CASE WHEN ins.type='run_started' THEN (ins.payload->>'stepsTotal')::int ELSE s.steps_total END,
    steps_running = s.steps_running
                    + CASE WHEN ins.type='started' THEN 1 ELSE 0 END
                    - CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
    steps_done    = s.steps_done    + CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
    steps_passed  = s.steps_passed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict'='pass' THEN 1 ELSE 0 END,
    steps_failed  = s.steps_failed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict' IN ('fail','blocked') THEN 1 ELSE 0 END,
    steps_timeout = s.steps_timeout + CASE WHEN ins.type='timeout' THEN 1 ELSE 0 END
FROM ins
WHERE s.id = $1;
```

If the row already existed (`DO NOTHING` → `ins` empty), the `UPDATE … FROM ins` matches no rows and the counters are untouched. Inserts may arrive out of order; counters are commutative so the final summary is correct regardless of order, and the timeline is always re-derived from `ORDER BY seq`.

## 6. Agent: event emitter

`runScenario` already tracks queued/started/completed per step (indexed results + an atomic completion counter) — so the emitter hooks the existing lifecycle points rather than adding new bookkeeping:

- before the scheduler runs: `run_started` (with `stepsTotal`);
- a job is enqueued → `queued`; a job begins → `started`; a job ends → `completed` / `timeout` / `killed`, with the verdict derived from the step's `ExecResult` (`TimedOut` → `timeout`; `parentCtx` cancel → `killed`; `Blocked` → verdict `blocked`; else `pass`/`fail` by exit code);
- after the scheduler drains: `run_completed` (or `run_cancelled` if `partial`).

**Emitter mechanics**
- A single goroutine owns a **bounded channel (`maxQueueSize = 1000`)**. Emit calls are non-blocking: if the queue is full (e.g. server unreachable), the emitter **drops the oldest event and logs once per drop-burst** — it never blocks or slows the run, and never grows unbounded against a dead server.
- The goroutine **flushes batches** to the server every ~300 ms or when ≥64 events are queued, whichever comes first, coalescing bursts of fast parallel completions into one request.
- Transport is **REST**, consistent with how the agent already sends heartbeats and results (no WS write-pump / concurrency / reconnect handling added to the agent).
- A flush failure drops that batch and moves on. The authoritative final POST is unaffected.

## 7. Server: ingest + relay

**New endpoint `POST /api/scenarios/events`** accepts a **batch** (array) of events:

```json
[ { "runId": "...", "seq": 11, "type": "started", ... },
  { "runId": "...", "seq": 12, "type": "completed", ... } ]
```

For each event the handler runs the idempotent insert+summary statement (§5.1), then relays the batch to browsers via the existing `hub.BroadcastBrowsers` (a `WSMessage{type:"run_event"}`). Browser relay is best-effort (the hub already drops on a full browser buffer); browsers reconcile from the DB on (re)load.

The authoritative `POST /api/scenarios/result` is **unchanged**: it still writes `results` + `score` and sets terminal status. On its arrival, results from the POST win (§3).

## 8. Capability negotiation

The agent advertises capability on enroll/heartbeat:

```json
{ "protocolVersion": 2, "emitsEvents": true }
```

- **Capable agent (`emitsEvents`):** posts events during the run as above.
- **Legacy agent:** never calls `/api/scenarios/events`; the server simply shows today's behavior (status `running` → final results). No forced upgrade — the endpoint and columns are purely additive. `protocolVersion` is carried now (cheap) so future protocol changes (e.g. B-2) can branch on it.

## 9. Live UI

A run-detail view subscribes to the browser WS and renders from events + the progress summary:
- a progress bar / counts: **`done / total`**, **`failed`**, and **`currently running: N`** (`steps_running`) — the running count is what tells an operator a concurrent run is *progressing* vs *stalled*, which becomes meaningful precisely because Phase A runs steps in parallel;
- a timeline list of steps with their current state (queued → running → verdict), ordered by `seq`;
- on `run_completed`, the view falls back to the authoritative final results for the detailed report.

The UI is the lightest part of this work; the event/summary **data contract** is the spec's focus and is what the plan must nail down first.

## 10. Resilience

Because terminal step events are persisted as they land, an agent or server crash (or a cancel) leaves **every completed step recorded in `run_events`** — the run is reconstructable instead of a total loss, and the progress summary reflects real progress. The already-shipped concurrency guard (one running scenario per agent) prevents an overlapping run from interleaving into the same stream. The final POST remains the authoritative reconciliation when the run does finish.

## 11. Testing

- **Idempotency:** inserting the same `(run_id, seq)` twice inserts once and increments counters once.
- **Out-of-order delivery:** deliver `seq 12, 11, 13`; the timeline (ordered by `seq`) reconstructs correctly and counters are correct regardless of arrival order.
- **Progress-summary math:** a scripted event sequence yields the expected total/done/running/passed/failed/timeout, including `running` returning to 0 at `run_completed`.
- **Legacy agent path:** an agent that never posts events still produces a completed run with correct final results.
- **Crash mid-run:** terminal events persisted before the crash survive and remain queryable; no double-counting on the agent's reconnect/retry.
- **Emitter never blocks:** with the server unreachable and the queue saturated, the run completes in the same wall-clock as with the server up (drops + logs, no stall).
- **Final POST authority:** when events and the final POST disagree, the stored `results`/`score` come from the POST (no merge).

## 12. File map (for the implementation plan)

- `orchestrator/internal/db/postgres.go` — `run_events` table + `scenario_runs` summary columns (additive migrations).
- `orchestrator/internal/models/` — `RunEvent` type; `WSMessage{type:"run_event"}`.
- `orchestrator/internal/api/handlers.go` + `routes.go` — `POST /api/scenarios/events` (batch, idempotent insert+summary, relay).
- `orchestrator/internal/ws/hub.go` — reuse `BroadcastBrowsers` (no change expected).
- `agent/types.go` — `RunEvent`; capability fields on heartbeat/enroll (`protocolVersion`, `emitsEvents`).
- `agent/agent.go` — bounded buffered emitter; hook emit points in `runScenario`; advertise capability.
- `orchestrator/wwwroot/` — run-detail live timeline + progress (done/total, failed, running).

## 12a. Implementation order

Build the **server side end-to-end first**, so the full ingest path is exercisable with curl/Postman-generated event batches before the agent is touched — which keeps feedback loops short and isolates failures to one side at a time:

1. **DB migration** — `run_events` table + `scenario_runs` summary columns.
2. **Server ingest endpoint** — `POST /api/scenarios/events` (batch).
3. **Progress summary updates** — the idempotent insert+counter statement (§5.1).
4. **WS relay** — broadcast received batches to browsers.
5. **Agent emitter** — bounded buffered emitter + hook emit points in `runScenario`.
6. **Capability negotiation** — advertise `protocolVersion`/`emitsEvents`.
7. **UI** — live timeline + progress.
8. **Tests** — the §11 set plus the §12b demos.

(Capability negotiation comes **after** the emitter: the emitter is independently testable, and negotiation only gates whether it runs.)

## 12b. Success criteria (acceptance demos)

B-1 is done when these are demonstrable:

1. **Live progress** — run a normal scenario; the UI shows `queued → started → completed` transitions live.
2. **Browser reconnect** — kill the browser tab and reconnect; the timeline reconstructs from persisted events (ordered by `seq`).
3. **Agent crash mid-run** — kill the agent partway; previously completed steps remain visible and correctly counted.
4. **Duplicate replay** — replay a duplicate event batch; counters remain correct (no double-count).
5. **Legacy agent** — an agent that emits no events still completes and scores correctly.

## 13. Non-goals / explicit deferrals

- Output-chunk streaming, batched dispatch, on-demand payloads → **B-2**.
- `workerId` / worker-identity in events → future enhancement, added inside `payload` (no schema change) when host-pool/worker diagnostics are needed. Keeps the event layer purely observational in B-1.
- Making events the source of truth / removing the final POST → not now (kept as the simple, robust overlay model).
