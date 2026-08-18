# Individual/Campaign/Scheduled Run Agent-Disconnect Resilience — Design

## Problem

Follow-up to the just-completed EM Sweep / Full Variant Sweep disconnect
resilience work
(`docs/superpowers/specs/2026-08-18-sweep-disconnect-resilience-design.md`).
The user asked twice for the same treatment to extend beyond the two sweep
types: *"it should not only for sweeps but should also for individuals and
all."*

## Investigation

Two findings reshape this into a much smaller problem than the sweep work:

**One shared code path, not three.** Individual ad-hoc runs, campaign
fan-out, scheduled assessments, and revalidation all dispatch through the
same `Handler.dispatchRun` (`internal/api/handlers.go:1287`) and write to
the same `scenario_runs` table (only Full Variant Sweep's per-variant
dispatch bypasses it, and that was already fixed). "Individuals and all"
is one fix, not three.

**The agent already self-heals a mid-run disconnect.** `agent/agent.go`'s
`runDisconnectWatchdog` (constants at `agent.go:338-339`:
`disconnectGracePeriod = 90 * time.Second`, matched deliberately to the
server's own `models.AgentOfflineAfter`) already detects when the link to
the server has been down for 90s while a run is active, locally cancels
that run, finalizes it as `partial`, and spools the result to submit the
moment it reconnects. Sweeps needed real pause/resume machinery because
the *server* decides what to dispatch next (the next layer); an individual
run has no next step for the server to decide — the agent already resolves
itself.

So the actual gap is narrower than sweeps:

1. Live Runs shows a stale "Running" badge for the window between
   disconnect and the agent's own watchdog finishing + reconnecting +
   submitting its spooled `partial` result.
2. If the agent is *permanently* gone (crashed, uninstalled,
   decommissioned), the run can sit "Running" indefinitely — the existing
   `runIsStale` / `staleRunGuard` (2 hours, `handlers.go:1169`) only fires
   *reactively*, triggered by `dispatchRun`'s own concurrency guard the
   next time something tries to dispatch to that same agent, which may
   never happen for a dead agent.

`cancelScenarioRun` already handles an offline agent correctly (marks
`partial` immediately, no error) and Stop is already visible the entire
time a row's `status === 'running'` — unlike sweeps, there is no missing
Stop button here to fix.

## Decisions

Confirmed with the user during brainstorming:

- **Scope**: fix the live "Running" display gap, and also add a proactive
  reaper for permanently-dead agents — not just the display fix alone.
- **Reap threshold**: 5 minutes of agent offline time before the server
  force-marks a `running` row `partial` on its own. Comfortably longer
  than the agent's own 90s watchdog + reconnect + spool-submit time, so
  the server essentially never races ahead of a temporarily-blipped agent
  that's about to resolve itself.
- **Connectivity signal**: reuse the existing `agents.last_update` +
  `models.AgentOfflineAfter` (90s) heartbeat-staleness definition — the
  same one `dispatchRun`'s own concurrency guard and `runIsStale` already
  use — rather than pulling the sweep work's live `Hub.IsAgentConnected`
  into a code path that has never depended on WS Hub state before. A
  display badge and a 5-minute reaper don't need sub-90-second precision.

## Design

### 1. Live display fix

`ListScenarioRuns` (`internal/api/handlers.go:2426`) already returns every
individual run row via the shared `scanRunRows` helper. `scanRunRows`
itself is not touched — its SELECT column order is a documented contract
shared by two other callers (`GetVexSweepRuns`, `GetEMSweepRuns`), and
those sweep-runs callers don't need this field (the sweep-level badge
already covers them from the prior work).

Instead, `ListScenarioRuns` does one lightweight follow-up query after
`scanRunRows` returns: for the distinct `agent_id`s among rows with
`status == "running"`, fetch which are stale
(`last_update < NOW() - 90s`), then sets a new `AgentDisconnected bool`
field (`json:"agentDisconnected,omitempty"`) on `runRow` for matching
rows. Purely a response-shape addition — no DB status change, no new
column, no touch to the `scanRunRows` contract.

Frontend: `runRowHtml` (`wwwroot/index.html:11066`) gets the same
`sweepStatusLabel`-style treatment — when `r.agentDisconnected` is true
and `r.status === 'running'`, the badge renders "Agent Disconnected"
(reusing the `.s-agent_disconnected` CSS class already added this
session) instead of "Running." Stop stays visible and functional exactly
as it is today — `cancelScenarioRun` already resolves it correctly
whether the agent is reachable or not.

### 2. Proactive reaper

New function `ReapAbandonedRuns` in `internal/api/liveness.go`, mirroring
`ReapNeverStartedRuns`'s existing shape in the same file:

- Query: `scenario_runs.status = 'running'` joined to `agents`, where
  `agents.last_update < NOW() - 5 minutes`.
- Action: for each match, `UPDATE scenario_runs SET status = 'partial',
  completed_at = NOW() WHERE id = $1 AND status = 'running'` — the exact
  same terminal status the agent's own watchdog already produces for a
  self-resolved disconnect. One terminal outcome for "didn't finish
  because the agent disconnected," regardless of which side resolved it,
  rather than a second, confusingly-similar status.
- Race safety: `SubmitScenarioResult` already has no status guard
  (established earlier this session — a late submission reconciles
  correctly regardless of the run's current status), so if the agent
  reconnects and submits moments after the reaper already marked the row
  `partial`, that submission still lands without conflict.
- **No campaign- or scheduled-assessment-specific code.** Campaign
  completion-detection (`campaign_handlers.go`) already reads
  `scenario_runs.status` generically per child row keyed on
  `campaign_id`. Once the reaper flips a child row to `partial`, campaign
  logic treats it as resolved with zero changes on that side — confirming
  the "one shared table, one fix" framing holds all the way through.
- **Out of scope, deliberately untouched**: `runIsStale`'s existing
  2-hour `staleRunGuard` path for a run wedged on a *still-connected*
  agent (the connected-but-genuinely-stuck case, not a disconnect at
  all) — same as sweeps left their own connected-but-stuck 3-minute timer
  untouched. This reaper only ever fires for the agent-offline condition.

Wiring: reuses the existing 30s-tick `dispatchWatchdogScheduler` in
`cmd/server/main.go` (currently calls only `ReapNeverStartedRuns`) — both
functions are run-liveness watchdogs living in the same file, checked at
the same cadence; no new scheduler goroutine needed.

## Testing

- `internal/api/handlers_test.go` or a new `liveness_test.go` case (mirror
  `runIsStale`'s existing table-driven tests in `liveness_test.go`):
  `ListScenarioRuns` sets `agentDisconnected` for a running row whose
  agent's `last_update` is stale, and leaves it unset/false for a running
  row on a live agent and for any non-running row.
- `ReapAbandonedRuns`: a `running` row on an agent offline past 5 minutes
  is marked `partial`; a `running` row on an agent offline under 5 minutes
  is untouched; a `running` row on a live agent is untouched regardless of
  run duration (that's `staleRunGuard`'s job, not this reaper's).
- A race-safety test mirroring the sweep work's pattern: `ReapAbandonedRuns`
  marks a row `partial`, then a subsequent `SubmitScenarioResult` call for
  that same run still succeeds and reconciles real results, proving no
  status-guard conflict.

## Out of scope

- No pause/resume machinery — the agent's own watchdog already handles
  resumption semantics; there is nothing analogous to a sweep's "next
  layer" for the server to decide here.
- No change to `cancelScenarioRun` or the Stop button — both already work
  correctly for a disconnected agent today.
- No change to `runIsStale`'s connected-but-stuck 2-hour path.
- No change to Full Variant Sweep's per-variant dispatch (`dispatchVariantRun`)
  — untouched by both this and the prior sweep work; it has its own
  separate WS-send path that was never covered by either fix's scope. If
  this needs the same treatment, it is a separate follow-up.
