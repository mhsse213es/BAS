# Verified Agent Uninstall — Design

**Date:** 2026-08-07
**Status:** Draft, pending user review

## Problem

"Remove Agent" in the Agents console today is purely a dashboard-record
change: `POST /api/agents/{agentId}/remove` sets `agents.state = 'retired'`
and nothing else. The code comment on that handler documents this as
intentional — "the agent software itself keeps running until someone
uninstalls it locally." Because retired agents are filtered out of the
default list view, clicking Remove Agent *looks* like it worked, but the
endpoint software is untouched. There is no way today to tell a live agent
to actually uninstall itself from the console.

## Goals

- A "Uninstall Agent" action that sends a real uninstall order to a
  connected endpoint, and only removes/updates the agent's record once the
  endpoint **confirms** the uninstall succeeded.
- If uninstall fails on the endpoint, the console surfaces the error
  instead of silently pretending it worked.
- Keep today's instant, connectivity-independent removal available as a
  clearly separate, explicitly-confirmed **Force Remove** escape hatch, for
  endpoints that are permanently gone (destroyed, wiped, decommissioned)
  and will never confirm anything.

## Non-goals

- Bulk/fleet-wide uninstall (e.g. "uninstall all agents in group X"). This
  operates on one agent at a time, from the row action menu, matching how
  Stop Agent and today's Remove Agent both work. Group-level bulk actions
  are a future System Tree extension, not built here.
- Queueing an uninstall for later delivery when an offline agent
  reconnects. Rejected explicitly (see Decisions below) — an uninstall
  command firing automatically, unattended, on an agent that reconnects
  days or months later is not acceptable for a destructive operation.
- Changing the Force Remove endpoint's shape, verb, or behavior. It is
  kept exactly as it is today.

## Decisions (from discussion)

1. **Two distinct operations, not one blended button.**
   - **Uninstall Agent** (new, primary/default action): requires a live
     connection, dispatches a real command, and only updates the agent's
     record once the endpoint reports success or failure. If the agent is
     offline when clicked, this **blocks with a clear error** — no silent
     queueing, no assumptions about a machine that might never come back.
   - **Force Remove** (existing behavior, kept as today's
     `POST /api/agents/{agentId}/remove`, unchanged on the backend):
     administrative record removal only, makes no claim about the
     endpoint's actual state, explicitly labeled as such, requires a
     separate confirmation.
2. **Force Remove keeps its existing route** (`POST .../remove`) rather
   than moving to `DELETE /api/agents/{agentId}`. It's already
   implemented, tested, RBAC-gated, and audit-logged; renaming the route
   for REST-purity alone is pure churn with no functional benefit.
3. **Reuse `CanRemoveAgent`** for the new Uninstall Agent endpoint — same
   admin-only family as Stop/Remove, no new permission needed.

## Current state (investigation findings)

- **`StopAgent`** (existing, closest pattern): dispatches
  `models.MsgCommandStopAgent` over the agent's WS connection; the agent's
  `stopSelf()` (`agent/agent.go`) disables auto-start and exits, but never
  touches its service registration, binary, or tray artifacts. Requires a
  live connection (503 otherwise).
- **`svcUninstall()`** (`agent/service.go`,
  `agent/service_linux.go`, `agent/service_darwin.go`) is a real, already
  cross-platform-implemented full uninstall — stops+deletes the service,
  removes tray autostart/shortcuts, and on Windows schedules the binary
  for delete-on-reboot (`agent/uninstall_windows.go`). Today it is only
  reachable **locally**, via the `agent.exe -uninstall` CLI flag
  (`agent/main.go`) — there is no server→agent command that triggers it.
- As a side effect, `svcUninstall()` calls `notifyServerUnenroll()`
  (`agent/unenroll.go` → `POST /api/agents/unenroll` →
  `internal/api.UnenrollAgent`, which sets `state='retired'`, identically
  to `RemoveAgent`). This call fires **before** the actual stop/delete
  steps, as a best-effort heads-up — not a confirmed-success signal. If
  the subsequent stop/delete fails, the server has already marked the
  agent gone. This is a real latent bug in the existing local-uninstall
  path, fixed as part of this work (see below).
- **Architectural wrinkle:** `svcUninstall()` is written for the CLI
  `-uninstall` flow, where a *separate, short-lived* process instance
  calls it to stop and delete an *independently running* service process
  via the OS service manager, then exits normally. A WS-triggered
  *remote* uninstall is different: the command arrives inside the
  **already-running service process itself**, which must ask the OS to
  stop and delete the very service it is running under, then report a
  result and exit — much closer to how `stopSelf()` already manages its
  own shutdown (used by Stop Agent) than to `svcUninstall()`'s
  separate-process model. This needs a dedicated in-process self-uninstall
  routine per platform, sharing the artifact-cleanup pieces (tray/registry
  removal, delete-on-reboot scheduling, systemd unit removal) with
  `svcUninstall()` where possible, but not reusing its stop-and-wait
  control flow wholesale. **This is flagged as an implementation risk to
  verify early** (a small spike: confirm a running Windows service can
  mark its own registration for deletion via `s.Delete()` and exit
  cleanly, and confirm the equivalent for `systemctl disable` on Linux and
  `launchctl unload` on macOS) — the plan should sequence this
  verification before building the rest of the flow on top of it.

## Design

### Data model

New `AgentState` values (`internal/models/schema.go`), alongside the
existing `active | restricted | quarantined | retired`:

- `uninstalling` — an uninstall command has been dispatched and the agent
  hasn't reported a result yet. Unlike `retired`/`uninstalled` below, this
  state stays in the **default** agent list (not filtered out) with an
  "Uninstalling…" badge — the admin needs to see it in progress, not have
  it disappear before it's confirmed. Nothing else about the agent's
  record changes while in this state.
- `uninstalled` — the endpoint confirmed a successful uninstall. Distinct
  from `retired` on purpose: `retired` means "an admin marked this gone
  without proof" (Force Remove today); `uninstalled` means "the endpoint
  proved it removed itself." Both are terminal, both are excluded from
  the default agent list the same way `retired` is today, and both are
  reachable via a "Retired" style filter for audit history.

New columns on `agents` (mirrors the existing `stopped_by` /
`stopped_at` / `stop_reason` pattern already on this table):

- `uninstall_requested_by TEXT`, `uninstall_requested_at TIMESTAMPTZ`,
  `uninstall_reason TEXT` — set when Uninstall Agent is dispatched.
- `uninstall_prior_state TEXT` — the agent's `state` immediately before
  dispatch, so a failed/timed-out attempt can restore it exactly instead
  of guessing.
- `uninstall_error TEXT`, `uninstall_error_at TIMESTAMPTZ` — set on a
  failed or timed-out attempt; cleared on the next successful attempt.
  Surfaced in the Agent Detail drawer as a persistent banner (not just a
  transient toast) until dismissed or superseded by a retry.

No hard FK constraints, matching every other table added this session.

### Backend

**`POST /api/agents/{agentId}/uninstall`** (new, `CanRemoveAgent`,
requires `reason` — same shape as Stop/Remove):
- If the agent isn't connected: **fails immediately** with 503 and a
  clear message ("Agent is offline — cannot verify uninstall. Retry once
  it reconnects, or use Force Remove for a permanently unavailable
  device."). No state change.
- If connected: dispatches a new WS command (`command_uninstall_agent`,
  `{reason}`), records `uninstall_requested_by/at/reason` and
  `uninstall_prior_state = <current state>`, sets `state = 'uninstalling'`,
  broadcasts `MsgAgentUpdate`, responds 200.

**`POST /api/agents/{agentId}/uninstall-result`** (new, agent-token
authenticated via the existing `validateAgentAuth` — same auth model as
`UnenrollAgent`): body `{success: bool, error?: string}`.
- On success: `state = 'uninstalled'`, clear `uninstall_error`/
  `uninstall_error_at` (keep the `uninstall_requested_*` fields for audit
  history). Broadcast `MsgAgentUpdate`.
- On failure: `state` reverts to `uninstall_prior_state`, set
  `uninstall_error`/`uninstall_error_at` to the reported message.
  Broadcast `MsgAgentUpdate`.
- Applied whenever it arrives, no matter how much time has passed since
  dispatch (idempotent, at-least-once delivery — same convention as this
  codebase's existing run-result reconciliation; no status guard blocking
  a "late" result).

**Timeout display** (not a background job — computed at read time, same
pattern as `EffectiveAgentStatus`): if `state == 'uninstalling'` and more
than a bounded window (proposed: 2 minutes — comfortably longer than the
existing `stopServiceAndWait` 15s internal timeout plus network latency)
has passed since `uninstall_requested_at` with no result received, `GetAgents`
presents the row as if `uninstall_error` were
"No response from the endpoint — it may have gone offline mid-uninstall."
without writing anything to the database. If the agent's result arrives
late, it is still applied normally.

### Agent side

New WS command handler for `command_uninstall_agent` (alongside the
existing `command_stop_agent` case in `agent/agent.go`): runs the
in-process self-uninstall routine (per the architectural note above),
then POSTs the result to `/api/agents/{agentId}/uninstall-result` **before**
exiting, then exits (matching `stopSelf()`'s clean-shutdown pattern —
disable auto-start, exit).

The existing `svcUninstall()` (local `-uninstall` CLI path) is also fixed
as part of this work: move its `notifyServerUnenroll()` call from before
the stop/delete steps to after, reporting the real outcome instead of an
optimistic pre-notify. This is a small, targeted fix to a real bug found
during investigation, not a broader refactor.

### Frontend

- Row action menu: "Uninstall Agent" replaces today's "Remove agent" as
  the primary destructive action. "Force Remove…" is added as a
  secondary, danger-styled, separately-confirmed action.
- "Uninstalling…" badge/spinner on the row while `state == 'uninstalling'`.
- Error banner in the Agent Detail drawer when `uninstall_error` is set,
  with Retry and Force Remove affordances.
- Force Remove confirmation dialog uses the exact copy already agreed:
  *"This removes the agent record from Audspect. The endpoint will not
  receive an uninstall command. The agent software may still be installed
  on the device if it ever reconnects. This action should only be used
  for permanently unavailable or decommissioned devices."*

### Audit logging

Two distinct audit actions: `agent.uninstall` (dispatch) and
`agent.uninstall_result` (outcome) for the new verified path;
`agent.remove` stays as today's action name for Force Remove — no
renaming, since it's the same unchanged endpoint.

## Testing plan

- Backend: dispatch success/offline-503, result success/failure updates,
  timeout display (pure function test, no DB write), Force Remove
  unchanged (existing tests already cover it).
- Agent: unit tests for the new self-uninstall routine per platform
  (mirroring the existing `uninstall_windows_test.go` style), and for the
  `notifyServerUnenroll` timing fix.
- Frontend: syntax check only, per this session's established convention;
  manual browser QA deferred to the same backlog as the Agent Group tree
  panel and other pending items (wwwroot is baked into the Docker image,
  not bind-mounted).
