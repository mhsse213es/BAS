# Endpoint Posture — Design Spec

**Sub-project E of the Unified Analytics Layer initiative — the last one.** Sub-projects A
(`internal/analytics` foundation), B (Unified Dashboard Shell), C (Detection Reconciliation), and D
(Threat Intel Summary) are all done and merged to `main`. This sub-project builds the "Endpoint
Posture" category the parent initiative's original decomposition named but never scoped — like D,
a genuine gap (Sub-project A's design doc: "no backend concept exists at all"), not a duplication
to reconcile.

## Goal

Build a fleet-wide endpoint posture summary — agent fleet health plus EPP protection state — that
doesn't exist today, and surface it on the Operational dashboard as a new widget alongside the
existing Threat Intelligence widget.

## Investigation: what endpoint data exists today, and where

- **`agents` table** (`internal/db/postgres.go:64-84`): `status` (`idle`/`scanning`/`offline`,
  heartbeat-driven), `state` (`active`/`restricted`/`quarantined`/`retired`, lifecycle —
  `models.AgentState`, `internal/models/schema.go:213-221`), `binary_trusted` (bool), `last_update`
  (timestamptz), `enrolled_at`.
- **`effectiveAgentStatus(stored, lastUpdate, now)`** (`internal/api/liveness.go:19-24`) — returns
  `"offline"` if `now.Sub(lastUpdate) > AgentOfflineAfter` (`90 * time.Second`,
  `liveness.go:11`), else the stored status. This is the fleet's **only** existing definition of
  "is this endpoint actually online" — `GetAgents` (`handlers.go:474`) and the stale-run reaper
  (`runIsStale`, `liveness.go:31`) both depend on it. **Both are unexported**, package-private to
  `internal/api`.
- **`action_requests` table** (`postgres.go:930-948`): one row per EPP response action
  (`internal/actions`, isolate/release/kill-process/quarantine-file against CrowdStrike/Defender).
  `status` is only ever persisted as `"completed"` or `"failed"` once `Execute` returns (v1 is
  synchronous, no queue — `actions.go:28-32`). `target_identifier` holds the hostname
  (`target_type = "hostname"`, the only implemented target type today). **There is no "is this host
  currently isolated" column anywhere** — it has to be derived from the latest completed
  isolate/release row per hostname.
- **No existing fleet-wide agent-health or EPP-state summary anywhere**: grepped
  `internal/dashboard`, `internal/analytics`, and every `agentCount`/`AgentCount` occurrence in the
  codebase — all of them are per-run or per-compliance-framework counts (e.g.
  `compliance.EnrolledAgentCount`, `reporting.CampaignScope.AgentCount`), not fleet health. This
  confirms Sub-project A's original framing: this category has never been built.

## A real architectural wrinkle: the import direction

`internal/analytics` cannot import `internal/api` (that's the reverse of the existing dependency
graph — `internal/api` already imports `internal/analytics`, e.g. `ti_handlers.go`,
`handlers.go`'s `GetCoverageAnalytics`) — importing it back would cycle. So `EndpointPosture` can't
call `internal/api`'s unexported `effectiveAgentStatus`/`AgentOfflineAfter` directly, and must not
reimplement the 90s-staleness rule as a second copy (this session's established rule: promote to
one canonical location, never duplicate a definition of "is this agent online").

## Decisions made during brainstorming

1. **Scope: fleet health + EPP protection state combined into one summary**, not two separate
   categories — mirrors how D combined actor-priority + KEV exposure under one Threat Intel
   umbrella, both because they're genuinely related (both describe "endpoint security posture")
   and to avoid a 6th sub-project for what's a small addition.
2. **This sub-project also touches the frontend**, like D — a new widget is added immediately
   rather than left for a future pass, since (like D) there's no existing dashboard consumer
   waiting for this data.
3. **`AgentOfflineAfter`/`effectiveAgentStatus` move to `internal/models`**, already imported by
   both `internal/api` and (after this sub-project) `internal/analytics`, and already the home of
   `Agent`/`AgentState`. `internal/api` is updated to delegate to the moved version — this is a
   pure relocation, not a new definition, so `GetAgents`'s existing behavior must stay byte-for-byte
   identical (verified by keeping its existing tests green before/after).

## Architecture

### 1. Move `AgentOfflineAfter` + effective-status logic to `internal/models`

In `internal/models/schema.go` (near the existing `Agent`/`AgentState` definitions):

```go
// AgentOfflineAfter is how long an agent can go without a heartbeat before
// it's considered offline regardless of its last-reported status. Single
// source of truth for the fleet's online/offline definition — comfortably
// exceeds the heartbeat interval to avoid flapping on one missed beat.
const AgentOfflineAfter = 90 * time.Second

// EffectiveAgentStatus returns "offline" if the agent's last heartbeat is
// older than AgentOfflineAfter, else the stored status.
func EffectiveAgentStatus(stored string, lastUpdate, now time.Time) string {
	if now.Sub(lastUpdate) > AgentOfflineAfter {
		return "offline"
	}
	return stored
}
```

`internal/api/liveness.go`'s `effectiveAgentStatus` and `AgentOfflineAfter` are deleted; its 2 call
sites (`handlers.go:474`, `liveness.go:32`'s `runIsStale`) and its own package-local references are
repointed to `models.EffectiveAgentStatus`/`models.AgentOfflineAfter`. No behavior change — same
constant value, same logic, just relocated.

### 2. `internal/analytics.EndpointPosture`

```go
func EndpointPosture(ctx context.Context, pool *pgxpool.Pool) (EndpointPosture, error)
```

Fleet-health portion: one query pulling `status, state, binary_trusted, last_update` for every
agent row, tallied in Go using `models.EffectiveAgentStatus` for the online/offline split (matching
`GetAgents`'s existing per-row logic exactly, just aggregated instead of returned per-agent).

EPP portion: a single SQL query using `DISTINCT ON` to get each hostname's most recent
isolate/release action, then counting how many of those latest rows are `endpoint.isolate`:

```sql
SELECT COUNT(*) FROM (
	SELECT DISTINCT ON (target_identifier) type
	FROM action_requests
	WHERE target_type = 'hostname'
	  AND type IN ('endpoint.isolate', 'endpoint.release')
	  AND status = 'completed'
	ORDER BY target_identifier, requested_at DESC
) latest
WHERE latest.type = 'endpoint.isolate'
```

```go
type EndpointPosture struct {
	TotalAgents          int `json:"totalAgents"`
	OnlineAgents         int `json:"onlineAgents"`
	OfflineAgents        int `json:"offlineAgents"`
	ActiveAgents         int `json:"activeAgents"`
	RestrictedAgents     int `json:"restrictedAgents"`
	QuarantinedAgents    int `json:"quarantinedAgents"`
	RetiredAgents        int `json:"retiredAgents"`
	UntrustedBinaryCount int `json:"untrustedBinaryCount"`
	CurrentlyIsolated    int `json:"currentlyIsolated"`
}
```

No pagination/limit — this is fleet-wide counts, not a list, so it stays a single cheap query
regardless of fleet size (matches the shape of every other `internal/analytics` summary category).

### 3. New handler `GET /api/analytics/endpoint-posture`

Thin call, same shape as every other category:

```go
func (h *Handler) GetEndpointPosture(w http.ResponseWriter, r *http.Request) {
	result, err := analytics.EndpointPosture(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

Registered `tierAny` (Viewer+), matching every other read-only analytics route (`rbac_matrix_test.go`
needs the matching entry — caught as drift by `TestRBACMatrix_NoDrift` last time if forgotten).

### 4. Frontend: new `#dash-endpoint-section` widget

Placed as a sibling immediately after the existing `#dash-ti-section` (`index.html:1474-1481`),
inside `#dash-view-operational`, using the identical hidden-until-loaded / KPI-tile-row structure:

```html
<!-- Endpoint Posture — fleet health + EPP isolation state; hidden until data is loaded -->
<div id="dash-endpoint-section" style="display:none">
  <div style="display:flex;align-items:center;justify-content:space-between;margin:1.25rem 0 0.55rem">
    <span style="font-size:0.72rem;font-weight:600;letter-spacing:0.06em;color:var(--muted);text-transform:uppercase">Endpoint Posture</span>
  </div>
  <div class="kpi-row" id="dash-endpoint-tiles"></div>
</div>
```

New `loadEndpointPostureWidget()` (called from wherever `loadKEVWidget()` is currently invoked on
dashboard load — same trigger point) fetches `/api/analytics/endpoint-posture` and renders up to 4
tiles: Online/Offline (e.g. "42 / 3"), Lifecycle breakdown (e.g. "40 active · 2 restricted · 1
quarantined"), Untrusted Binaries (only shown if > 0, danger-colored, matching the existing
"only render if nonzero" convention `loadKEVWidget` already uses for its own visibility gate), and
Currently Isolated (only shown if > 0). Clicking any tile calls `showTab('agents')` — no new
click-through target needs inventing, the Agents tab already exists and already shows this exact
per-agent data.

## Non-goals

- No new database tables/columns/migrations — every field comes from `agents`/`action_requests` as
  they exist today.
- No change to `GetAgents`, the Agents tab, or `internal/actions`/`action_handlers.go` — this is a
  read-only fleet-wide aggregation layered on top, not a change to per-agent behavior.
- No posture-*check* pass/fail data (the `posture_catalog` picker, per-OS deferred-exec checks) —
  investigated and confirmed that's a catalog of available checks agents can run, not a store of
  check *results*; results would flow through `scenario_runs` like any other technique, which is
  already covered by Detection Reconciliation (Sub-project C). Mixing it in here would conflate two
  different meanings of "posture."
- No `internal/intelligence`/`internal/threatgraph` involvement — unrelated to endpoint fleet state,
  already scoped out of D for the same reason.

## Testing

`internal/models`: a regression-guard test for `EffectiveAgentStatus` (moved logic) covering the
same online/offline/stale cases `internal/api`'s existing tests already implicitly cover, run
before and after the move.

`internal/analytics/endpoint_test.go`, same `TestMain`/`sharedDB` pattern as every other category:
seeded agents covering all 4 lifecycle states, an online agent (`last_update = NOW()`), an offline
agent (`last_update` older than 90s), an untrusted-binary agent; seeded `action_requests` covering
a bare completed isolate (counts as isolated), an isolate followed by a completed release (does
not count as isolated), and a failed isolate (does not count — `status != 'completed'`).

`internal/api/endpoint_posture_handler_test.go`: one test confirming the handler returns 200 and
delegates correctly against a minimal seeded fleet.

Frontend verification matches Sub-project B/D's convention (no automated test harness for
`index.html`): Node syntax check on every inline `<script>` block, plus a DOM id-uniqueness check
for `dash-endpoint-section`/`dash-endpoint-tiles`.
