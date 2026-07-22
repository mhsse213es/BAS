# Remote Agent Stop — Design Spec

**Goal:** give an Admin operator a "Stop" action in the Agents table that durably stops a connected BAS agent on its endpoint — the process stops, and it does not come back on its own (not on a service-recovery restart, not on the endpoint's next reboot). There is no remote way to start it again afterward; that requires physical/console access to the endpoint.

**Why now:** operators currently have no way to pull an agent out of service short of physically uninstalling it. This came up directly as a request to add a Stop/Offline action next to the existing per-agent buttons (Detail / Run / Safe Scan / Report / Pack) in the Agents table.

**Explicitly not this feature:** the existing `PUT /api/agents/{agentId}/state` (active/restricted/quarantined/retired) is a *dispatch-policy* flag — it blocks scenario runs server-side but the agent process keeps running and heartbeating. This feature is a different thing: actually terminating the agent process on the endpoint. The two are unrelated and this spec does not change `state` semantics.

---

## Architecture

### Delivery: server → agent

Reuses the existing targeted WebSocket command pattern already used for scenario dispatch and `command_cancel` (`orchestrator/internal/ws/hub.go:109` `SendToAgent`, and the agent's WS read-loop switch in `agent/agent.go:884`).

1. New WS message type constant in `orchestrator/internal/models/schema.go` (alongside the existing `MsgCommand*` constants at line ~305): `MsgCommandStopAgent = "command_stop_agent"`. Payload: `{"reason": string}`.
2. New endpoint `POST /api/agents/{agentId}/stop`, Admin-only via a new permission `CanStopAgent` (mirrors `CanExecuteResponseAction`'s Admin-only precedent — this is at least as consequential as an EPP response action). Body: `{"reason": string}`, reason mandatory (400 if empty, same pattern `SetAgentState` uses for its own body validation at `handlers.go:466`).
3. Handler flow (new function `StopAgent` in `handlers.go`, placed near `SetAgentState`):
   - Validate reason non-empty → 400.
   - `h.hub.SendToAgent(agentID, models.WSMessage{Type: models.MsgCommandStopAgent, AgentID: agentID, Data: map[string]string{"reason": reason}})`. If `sent == false` → `503 agent not connected` (matches the exact pattern `TriggerScan`/`FullScan` already use — see `handlers.go:786-791`).
   - On success: `UPDATE agents SET stopped_by = $1, stopped_at = NOW(), stop_reason = $2 WHERE agent_id = $3`, where `$1` is `claims.UserID` from `auth.ClaimsFrom(r.Context())` — same identifier `audit_logs.actor_id` already stores (see `auditLog` at `audit.go:44`), not a display name. Resolving it to something human-readable is a read-time join, not a write-time choice (see below).
   - `h.auditLog(r, "agent.stop", agentID, map[string]any{"reason": reason}, "ok")`.
   - `h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})` so open dashboards refresh without a manual reload.
   - Respond `200 {"agentId": agentID, "status": "stop_dispatched"}`.
4. Route wiring in `routes.go` next to the existing agent-state route (line 343): `r.With(auth.RequirePermission(auth.CanStopAgent)).Post("/api/agents/{agentId}/stop", h.StopAgent)`.

The dispatch is fire-and-forget over WS (no ack protocol exists for any command in this codebase today — matches the established at-least-once pattern), so `stopped_by`/`stopped_at`/`stop_reason` are persisted optimistically on successful *send*, not on confirmed execution. This is consistent with how scenario dispatch already records "dispatched" without waiting for the agent to actually start running.

### Agent-side: receiving and executing the stop

New case in the WS message switch (`agent/agent.go:884`, alongside `command_cancel`):

```go
case "command_stop_agent":
    var body struct{ Reason string `json:"reason"` }
    if err := json.Unmarshal(msg.Data, &body); err != nil {
        log.Printf("[!] WS: bad stop command: %v", err)
        continue
    }
    go a.stopSelf(body.Reason)
```

New shared method (cross-platform, in `agent/agent.go` or a new small `stop.go`):

```go
// stopSelf performs a durable, operator-requested shutdown: finalize any
// in-flight run, send a final heartbeat, disable the platform service so it
// does not come back (not on crash-recovery, not on next boot), then exit.
// Reuses the same finalize/heartbeat sequence as a normal graceful shutdown.
func (a *Agent) stopSelf(reason string) {
    log.Printf("[*] Stop requested by operator: %s", reason)
    a.logger.Op("warn", "lifecycle", "agent stopped by operator request: "+reason)
    a.shutdownFinalize(shutdownGrace)
    a.sendHeartbeat("offline")
    platformRestoreOnShutdown()
    if err := platformDisableAutoStart(); err != nil {
        log.Printf("[!] disable auto-start: %v — agent may restart at next boot", err)
    }
    platformExitAfterStop()
}
```

`platformDisableAutoStart()` and `platformExitAfterStop()` are new platform-specific functions, one implementation per OS. The split exists because each platform's service manager has a *different* auto-restart guard that a naive "just exit the process" would trip:

- **Windows** (`agent/service.go`): the service already has anti-tamper auto-restart — `ApplyServiceRecovery()` configures `sc failure BASAgent ... actions=restart/60000/restart/60000/restart/60000` (restart ×3 at 60 s intervals). This recovery policy fires on a *failure* exit (SCM sees the process die without a matching `SERVICE_STOPPED` status transition it initiated), not on a clean stop. So `platformExitAfterStop()` must not just call `os.Exit()` — doing so while `svc.Run()` is active skips the SCM handshake and would look like a crash, triggering the recovery restarts. Instead:
  - `platformDisableAutoStart()`: `mgr.Connect()` → `OpenService("BASAgent")` → `s.Config()` → set `StartType = mgr.StartDisabled` → `s.UpdateConfig(cfg)`. Safe to call on a running service; only affects the *next* start attempt.
  - `platformExitAfterStop()`: if `isWindowsService()` (service.go:256), send on a new package-level channel `stopRequested = make(chan string, 1)` and return. `agentSvc.Execute()`'s select loop (`service.go:59`) gets a new `case reason := <-stopRequested:` doing exactly what `case svc.Stop, svc.Shutdown:` already does (`status <- svc.Status{State: StopPending, ...}`, then `return false, 0`) — this is the same clean-exit path SCM already treats as a non-failure, since finalize/heartbeat were already done by `stopSelf` before this fires. If not running as a service (console mode), fall through to `os.Exit(0)` directly — no SCM handshake exists in that mode.

- **Linux** (`agent/service_linux.go`): the systemd unit has `Restart=on-failure` (line 55) — a clean exit (code 0) already will not trigger it. `platformDisableAutoStart()`: `exec.Command("systemctl", "disable", "bas-agent.service").Run()` (best-effort — log and continue on error rather than abort the stop). `platformExitAfterStop()`: `os.Exit(0)`.

- **macOS** (`agent/service_darwin.go`): the launchd plist has `KeepAlive` (line 47) set to the boolean `true` — this restarts the job unconditionally on *any* exit, clean or not, unlike the other two platforms' failure-only policies. This means the ordering in `stopSelf` (disable happens *before* exit) is load-bearing here, not just tidy: if the process exited first, launchd would relaunch it before the disable step ever ran. `platformDisableAutoStart()`: `exec.Command("launchctl", "unload", "-w", darwinPlistPath).Run()` — the `-w` flag persists the disabled state so it also does not come back on next boot. Documented limitation: `launchctl unload` synchronously terminates the job, so this may kill the process before or during its own `.Run()` call returns — `platformExitAfterStop()`'s explicit `os.Exit(0)` becomes a no-op in that case (process is already gone), which is fine. Net effect: on macOS the final "offline" heartbeat sent by `stopSelf` a few lines earlier is a best-effort, not a guarantee — the server should not require it to confirm the stop; `stopped_by`/`stopped_at` from the dispatch record is the authoritative signal, and the agent going quiet (no more heartbeats) is corroborating evidence, not a required confirmation.

### Data model

New columns on `agents` (idempotent migration alongside the existing ones in `orchestrator/internal/db/postgres.go:79-88`):

```sql
ALTER TABLE agents ADD COLUMN IF NOT EXISTS stopped_by  text
ALTER TABLE agents ADD COLUMN IF NOT EXISTS stopped_at  timestamptz
ALTER TABLE agents ADD COLUMN IF NOT EXISTS stop_reason text
```

`models.Agent` (`orchestrator/internal/models/schema.go:235`) gets four new optional fields — `StoppedBy` holds the raw user ID (matches `audit_logs.actor_id`'s convention), `StoppedByName` is the read-time-resolved display name for the UI banner:

```go
StoppedBy     *string    `json:"stoppedBy,omitempty"`
StoppedByName *string    `json:"stoppedByName,omitempty"`
StoppedAt     *time.Time `json:"stoppedAt,omitempty"`
StopReason    *string    `json:"stopReason,omitempty"`
```

`GetAgents` (`handlers.go:423`) SELECT/Scan extended to include the three DB columns plus a `LEFT JOIN users u ON u.id = a.stopped_by` resolving `COALESCE(u.username, a.stopped_by)` as `StoppedByName` — the exact same resolution pattern `GetAuditLogs` already uses for `actor_name` at `audit.go:93,96`.

**Clearing on re-enroll:** a fresh enrollment is itself evidence someone physically restarted the agent (matches the existing precedent — `EnrollAgent`'s upsert already resets `state` back to `active` unless it was `quarantined`/`retired`, at `handlers.go:702-705`). Add `stopped_by = NULL, stopped_at = NULL, stop_reason = NULL` to the same `ON CONFLICT DO UPDATE SET` clause unconditionally (no quarantine-style carve-out needed — if it re-enrolled, it's no longer stopped, full stop).

### Permission

New permission in `orchestrator/internal/auth/permissions.go`, alongside `CanExecuteResponseAction` (line 138):

```go
CanStopAgent Permission = "agents:stop"
```

Admin-only (added to the Admin role's permission set the same way `CanExecuteResponseAction` is, at `permissions.go:215`). Update the permission-matrix fixture tests (`TestHasPermission_MatrixIsComplete`, `TestPermissions_Ordering` — same two tests Plan 4 of EPP Response Actions had to update, not `TestPermissionGrants_MatchMigrationInventory`, which stays scoped to its historical migration snapshot) and the RBAC drift test (`internal/api/rbac_matrix_test.go`, add one `routeMatrix` entry for the new route).

---

## UI

**Agents table (`orchestrator/wwwroot/index.html`, `renderAgentRows` at line 5555):** new "Stop" button in the Actions cell (line 5575-5583), alongside Detail/Run/Safe Scan/Report/Pack. Admin-only (`ROLE === 'admin'`, string omitted from the row's HTML entirely when not admin — same hidden-not-disabled convention as every other admin-gated control on this page, e.g. `pushBtn`/`respondBtn` in `openFinding`). Shown only when the agent is connected: `a.status !== 'offline'` (mirrors `agentBucket()`'s own online/offline check at line 5520-5524) — stopping an already-offline agent has nothing to dispatch to.

**Confirmation modal:** new `#stop-agent-overlay`, same visual pattern as the Respond modal added for EPP Response Actions (`#respond-overlay`) — target hostname shown, mandatory Reason field, and explicit warning text: *"This stops the agent and disables it from restarting automatically — including after a reboot of this endpoint. There is no remote way to start it again; someone will need physical or console access to the machine."* Submit button disabled until Reason is non-empty (same client-side validation pattern `submitRespondAction` uses). On submit: native-feeling `confirm()` echoing hostname + reason, then `POST /api/agents/{agentId}/stop`. On success: toast, close modal, refresh the agents list (`loadAgents()`).

**Agent Detail view (`openAgentDetail`, ~line 12520-12560):** new persistent banner shown when `a.stoppedBy` is set, in the same style/position as the existing quarantined/restricted/retired banners (lines 12537-12539): *"Agent was stopped by \<stoppedByName\> on \<stoppedAt\>: \<stopReason\>. It will not restart automatically. Physical/console access to the endpoint is required to bring it back."*

---

## Error handling / edge cases

- **Agent not connected at dispatch time** → `503`, UI toast "Agent is not currently connected — cannot stop." No state persisted (nothing was sent).
- **`platformDisableAutoStart()` fails on the agent** (e.g. permissions issue, SCM unreachable) → logged, but the stop proceeds anyway (finalize + heartbeat + exit already happened or are about to). The agent does stop now; it just isn't guaranteed to stay stopped across a reboot. This is a real, disclosed gap — not silently swallowed, but not a reason to abort an otherwise-working stop either.
- **Double-stop** (operator clicks Stop twice, or the WS message arrives twice under at-least-once delivery): `stopSelf` runs twice is harmless — `shutdownFinalize`/`sendHeartbeat`/`platformDisableAutoStart` are all idempotent no-ops on a second call (nothing in-flight to finalize, disable-already-disabled is not an error for `sc config`/`systemctl disable`/`launchctl unload`), and the process can only exit once regardless.
- **macOS heartbeat race** — see the macOS section above. Documented as expected behavior, not a bug to chase.

## Out of scope (deferred)

- **Remote start/restart.** Explicitly not built — the user selected this option knowing it means physical/console access is required afterward. No WinRM/SSH/remote-exec capability exists in this platform today (confirmed absent per the integrations-gap review) to build this on top of even if desired later.
- **Non-Admin visibility of who/why an agent was stopped** beyond the Detail-view banner (e.g. a dedicated "Stopped Agents" filter/report) — not requested, YAGNI for v1.
- **Bulk stop** (multi-select stop across several agents at once) — not requested.

---

## Testing

- Backend: table-driven test for `StopAgent` (missing reason → 400; agent not connected → 503; success → 200 + DB columns set + audit log row written), following the exact test-harness conventions already established in `action_handlers_test.go` (Plan 4 of EPP Response Actions) — `auth.ContextWithClaims`, `authedRequest`/`callAuthed`, `sharedDB.RunWithPool`.
- Agent: unit test for the WS message unmarshal + dispatch (`command_stop_agent` → `stopSelf` called with the right reason), and platform-specific tests for `platformDisableAutoStart`/`platformExitAfterStop` where feasible without a live SCM/systemd/launchd (likely thin — most of this is only meaningfully verifiable via a live-server smoke test / manual checklist, matching how Windows-service-specific code has been handled elsewhere in this codebase, e.g. `pool_windows_test.go`).
- UI: structural grep verification + live-server smoke test for the new markup (same pattern as every prior UI plan this session), plus a manual browser checklist for the actual stop-and-confirm flow (cannot be automated — no browser automation tool available in this environment, same disclosed limitation as every prior UI plan).
- Full regression: `go test ./...` for the orchestrator (agent-side tests run separately, native Windows build, per this session's established pattern).
