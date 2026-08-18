# Sweep Agent-Disconnect Resilience — Design

## Problem

Reported by the user via direct testing: they stopped the agent Windows
service mid-way through an Endpoint Mastery Full Sweep. Three things went
wrong:

1. Live Runs kept showing the sweep as **"Running"** — false, since the
   agent was gone.
2. There was **no way to Stop** the sweep from that state — the Live Runs
   row's actions cell has no Stop button at all (only a "View" link into a
   progress drawer, which does have one). This matters because a
   disconnect can be the user's own intentional action (they stopped the
   service on purpose) and they should be able to definitively cancel
   rather than being stuck.
3. When the agent's service was restarted and it reconnected, **the sweep
   was gone** — silently failed in the background — rather than resuming.

## Root Cause

`internal/emsweep/dispatcher.go`'s `Dispatcher.advance()` has no concept of
"agent connectivity." It only has a wall-clock `stuckThreshold` (3 minutes,
`dispatcher.go:36`) that treats "the agent is gone" and "the agent is
connected but genuinely hung on a slow check" identically:

- 3 minutes after disconnect, `maybeForceCancelStuck` force-cancels the
  in-flight layer.
- The next tick's `dispatchNext` (`dispatcher.go:129`) tries to dispatch
  the *next* layer. `internal/api/em_dispatch.go`'s `dispatchEMLayer`
  calls `dispatchRun`, whose `h.hub.SendToAgent` fails immediately (agent
  still offline) and returns `skip = "offline"`. `dispatchEMLayer` turns
  that non-nil skip into a hard `fmt.Errorf`.
- Back in `dispatchNext`, that error triggers
  `d.store.MarkFailed(ctx, sw.ID, err.Error())` — the **entire sweep**
  dies, typically minutes before the user has even restarted the service.

`internal/vexsweep/dispatcher.go` has the identical pattern for Full
Variant Sweep and gets the identical fix (confirmed by the user during
brainstorming — this covers both sweep types, not EM Sweep alone).

Two mechanisms already exist and do **not** need to be rebuilt:

- **Connectivity signal**: `ws.Hub` already tracks connected agents
  in-memory (`SendToAgent`, `ConnectedAgents()` at `hub.go:187`). Nothing
  today exposes a live "is this specific agent connected" check to the
  sweep dispatchers — that's the actual gap.
- **Offline-safe cancel**: `Handler.cancelScenarioRun` (`handlers.go:2488`)
  already marks a run `'partial'` with no error when the target agent is
  unreachable. `CancelEMSweep`/`CancelVexSweep` already call this
  correctly. The only real defect in the Stop path is that
  `CancelEMSweep`/`CancelVexSweep` reject with 409 unless
  `sw.Status == "running"` — once this design introduces a distinct
  `agent_disconnected` status, that guard must accept it too, or Stop
  breaks in exactly the state the user needs it in.

## Decisions

Confirmed with the user during brainstorming:

- **Scope**: fix both EM Sweep (`internal/emsweep`) and Full Variant Sweep
  (`internal/vexsweep`) — same bug, same fix shape in both.
- **Resume behavior**: on reconnect, re-dispatch the interrupted layer
  *from scratch* as a fresh run. It has no usable partial result (either
  never dispatched, or cut off mid-execution), so nothing is skipped or
  silently dropped from the sweep's results.
- **Give-up timeout**: none. A disconnected sweep waits indefinitely for
  the agent to reconnect. It only ever leaves the disconnected state via
  reconnect (resume) or an explicit Stop. No arbitrary duration to
  configure or justify.
- **Status representation**: a real, persisted status value
  (`agent_disconnected`) on the sweep row — not a frontend-only display
  computation. The dispatcher itself needs a real state to branch its
  pause/resume logic on; a display-only label wouldn't actually fix the
  resume bug, only the cosmetic one.

## Design

### 1. Connectivity signal

Add `Hub.IsAgentConnected(agentID string) bool` (`ws/hub.go`) — same
`RLock` + map-lookup pattern as the file's other read methods, O(1)
instead of building a slice via `ConnectedAgents()` and scanning it.

### 2. Data model

For both `em_sweeps` and `vex_sweeps`:

- New status value `agent_disconnected`, usable alongside the existing
  `running` / `completed` / `failed` / `stopped`. No schema change needed
  for the column itself (`status text`, no CHECK constraint today).
- New nullable column `disconnected_at timestamptz`, mirroring the
  existing `started_at`/`completed_at` pattern — lets the UI show "since
  HH:MM" and gives the dispatcher a clean place to record the transition
  moment.
- The partial unique index enforcing "one active sweep per agent"
  (`idx_em_sweeps_one_running_per_agent`, `idx_vex_sweeps_one_running_per_agent`
  — both `WHERE status = 'running'`, `postgres.go:670-671` and `694-695`)
  must also treat `agent_disconnected` as active, otherwise a second sweep
  could be started against an agent whose first sweep is merely
  disconnected, not finished. Since `CREATE UNIQUE INDEX IF NOT EXISTS`
  won't redefine an existing index under an unchanged name, this requires
  an explicit `DROP INDEX IF EXISTS` + recreate with
  `WHERE status IN ('running', 'agent_disconnected')`, added as a new
  guarded migration statement (matching the file's existing evolutionary
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` style, e.g. `postgres.go:1529`).
- `Store.ListRunning` (both packages) currently backs `Dispatcher.Tick`'s
  per-tick sweep of active sweeps and only selects `status = 'running'`.
  Rename/replace with `ListActionable` selecting
  `status IN ('running', 'agent_disconnected')` — a disconnected sweep
  must keep being ticked so the dispatcher can notice a reconnect.
- `Store.GetActiveForAgent` (used to block starting a second sweep for an
  already-sweeping agent) gets the same `IN (...)` widening.
- `Sweep` struct (both packages) gains `DisconnectedAt *time.Time`.

### 3. Dispatcher state machine

`Dispatcher` (both packages) gains one new injected function, matching the
existing `dispatch`/`cancel`/`status` injection pattern used to avoid an
`internal/emsweep` → `internal/api` import cycle:

```go
type ConnectedFn func(agentID string) bool
func (d *Dispatcher) SetConnected(fn ConnectedFn)
```

Wired in `cmd/server/main.go` as `emSweepDispatcher.SetConnected(hub.IsAgentConnected)`
(and the `vexSweepDispatcher` equivalent), next to the existing
`SetDispatch`/`SetCancel` wiring.

`advance()` checks connectivity for `sw.AgentID` **before** today's
status/stuck-timer logic, every 5s tick:

| Sweep status | Agent connected? | Action |
|---|---|---|
| `running` | yes | **Unchanged.** Today's existing stuck-timer/force-cancel logic for a genuinely-hung-but-connected layer keeps working exactly as it does now. |
| `running` | no | Transition → `agent_disconnected`, set `disconnected_at = now()`. If there's an in-flight run (`CurrentScenarioRunID != ""`), cancel it via the existing `cancel` fn — since the agent is offline this resolves immediately to `'partial'`, no grace-period wait, reusing the exact mechanism `CancelEMSweep` already relies on. `CurrentIndex` is **not** advanced — it still names the interrupted layer. Detected within one tick (~5s), a large improvement over today's 3-minute delay. |
| `agent_disconnected` | no | No-op — wait. The stuck-timer is skipped entirely in this state; "disconnected" is a known condition now, not an unexplained stall, so the indefinite-wait rule applies here, not the 3-minute one. |
| `agent_disconnected` | yes | **Resume.** Transition → `running`, clear `disconnected_at`, re-dispatch `Layers[CurrentIndex]` as a fresh run via the existing `dispatchNext` dispatch call, setting a fresh `CurrentLayerStartedAt`. |

**Race window defense-in-depth:** between the connectivity check and the
dispatch call actually going out, the agent could still drop. For this one
case, `internal/api/em_dispatch.go`'s `dispatchEMLayer` (and the vexsweep
equivalent) changes its offline case to return a sentinel
(`emsweep.ErrAgentOffline`) instead of a generic `fmt.Errorf`.
`dispatchNext` special-cases `errors.Is(err, ErrAgentOffline)` into the
same `agent_disconnected` transition above, instead of calling
`MarkFailed`. Every other error `dispatchEMLayer` can return (bad
scenario ID, DB error, etc.) still hard-fails the sweep exactly as today —
only the specific "agent unreachable" case gets the softer handling.

### 4. API

- `CancelEMSweep` / `CancelVexSweep`: the guard
  `if sw.Status != "running"` → `if sw.Status != "running" && sw.Status != "agent_disconnected"`.
  Cancelling a disconnected sweep cancels the (already-offline, so
  immediately-`partial`) in-flight run if any, then `MarkStopped` exactly
  as today.
- `emSweepToJSON` / the vexsweep equivalent: add `disconnectedAt` to the
  response.

### 5. Frontend (`wwwroot/index.html`)

- `renderEMSweepRow` (`:11180`) / `renderSweepRow` (vexsweep equivalent):
  - Status badge: map `agent_disconnected` → label "Agent Disconnected",
    new `.s-agent_disconnected` CSS class styled as a distinct warning
    color — not the "running" color, not the "failed" red.
  - Actions cell (currently `<td>—</td>` — no action at all) gets a
    "Stop" button whenever `sw.status` is `running` or
    `agent_disconnected`, calling the cancel endpoint directly. This is
    the direct fix for "no option of Stop" — no need to open the
    progress drawer first.
- The progress drawer (`openEMSweepProgress` and vexsweep equivalent)
  picks up the same status label/badge treatment wherever it already
  renders `sw.status`.

## Testing

- `internal/emsweep/dispatcher_test.go` / `internal/vexsweep/dispatcher_test.go`:
  new cases using fake `connected`/`dispatch`/`cancel` functions (same
  shape as the file's existing `stuckThreshold`-shrinking tests) covering:
  disconnect-detected transition (running → agent_disconnected, in-flight
  run marked partial, index unchanged); no-op while disconnected (stuck
  timer does not fire); reconnect-resume (agent_disconnected → running,
  same layer re-dispatched, fresh `CurrentLayerStartedAt`); the
  `ErrAgentOffline` race-window path (soft transition, not `MarkFailed`).
- `internal/api/emsweep_handlers_test.go` / vexsweep equivalent: cancel
  succeeds (200, not 409) when sweep status is `agent_disconnected`.
- `internal/api/rbac_matrix_test.go`: no new routes, so no matrix changes
  expected — confirm at plan time.

## Out of scope

- No bounded give-up timeout (explicitly rejected — wait indefinitely).
- No change to the existing connected-but-stuck 3-minute force-cancel
  behavior — untouched by this design.
- No per-layer/run-level status display changes beyond the sweep-level
  badge and drawer — the user's report was about the Live Runs sweep row,
  not individual layer rows inside the drawer.
