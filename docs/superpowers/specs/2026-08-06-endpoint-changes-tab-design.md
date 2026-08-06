# Endpoint Changes Tab (V1) — Design Spec

**Goal:** Populate the "Endpoint Changes" tab in the per-run results drawer (`orchestrator/wwwroot/index.html`, `run-tab-endpoint`) — the last of 5 placeholder tabs, currently a static "not available yet" message — with real data.

**Scope decision (made during brainstorming, corrected mid-investigation):** the user initially asked for a "real structured capture" system (files/registry/processes/services as new agent-side capture). Investigation found this framing was based on an incomplete picture: a whole-run before/after snapshot-and-revert system already exists, is already fully wired end to end, and already covers most of the originally-requested scope. **V1, this spec, is scoped to exposing that already-captured data** — small, low-risk, mirrors the Timeline/MITRE tabs' "reuse what's already flowing" pattern. A real, separate gap found during investigation (failed/leaked changes are invisible) is explicitly out of scope here and deferred to a V2 design.

## Investigation: what already exists (verified, not assumed)

An initial investigation this session concluded the existing snapshot system was dead code with zero call sites — **this was wrong**, caused by grepping for the wrong identifiers (`newSnapshot`/`SystemSnapshot` as substrings, which don't appear in an actual call like `captureSnapshot(cmd.RunID)`). Corrected via direct verification:

- **`agent/snapshot.go` + `snapshot_windows.go`/`snapshot_posix.go`** define `SystemSnapshot` (`Lists map[string][]string`, `Files map[string][]byte`) and two entry points: `captureSnapshot(runID string) *SystemSnapshot` and `revertFromSnapshot(s *SystemSnapshot) []string`. On Windows, `captureSnapshot` records registry Run/RunOnce keys, services, scheduled tasks, temp-directory listings, the hosts file, firewall rules, and startup-folder entries; `revertFromSnapshot` re-checks each category, **deletes/stops anything new**, and returns one human-readable string per successfully-reverted item (e.g. `"registry removed: HKLM\...\Run\X"`, `"schtask deleted: Y"`, `"service stopped: Z"`).
- **This is actively called on every run**: `snap := captureSnapshot(cmd.RunID)` at `agent/agent.go:457` (before any step executes), `reverted := revertFromSnapshot(snap)` at `agent/agent.go:635` (after the scheduler drains, before result submission).
- **The result is submitted to the server**: `agent/agent.go:639` calls `a.submitResults(cmd, final, partial, reverted)`, which builds `scenario.RawRunResult{..., Reverted: reverted}` (`agent/agent.go:671`) and POSTs it to `/api/scenarios/result`.
- **The server stores it**: `orchestrator/internal/api/handlers.go:2008-2010` marshals `raw.Reverted` to `revertedJSON`, persisted via `UPDATE scenario_runs SET ... reverted = $4::jsonb ...` (`handlers.go:2039-2046`) — confirming the `scenario_runs.reverted` column is `jsonb`.
- **It's already read back and rendered elsewhere**: `internal/reporting/engine.go:139` (`FullReport.Reverted []string`, populated via `json.Unmarshal(revertedRaw, &report.Reverted)` at `engine.go:1398`/`1646`), used by `buildEnvRestoration` (`engine.go:3200`, an aggregate summary — cleanup rate/coverage rate/status label, not the itemized list) for the report's "Environment Restoration" section, and rendered as a literal bulleted list of every individual item in the PDF report (`internal/reporting/pdf.go:1472-1489`, with framing text: `"The agent reverted %d endpoint change(s) made during the run."` / a "No endpoint changes were captured..." empty state at `pdf.go:1474-1476`).
- **What's missing**: the dashboard's per-run drawer does not currently have this data. `viewRunResults(run)` (`wwwroot/index.html:10551`) receives `run` objects populated from `GET /api/scenarios/runs` (`ListScenarioRuns`, `internal/api/handlers.go:2197`), whose SQL query (`handlers.go:2201-2208`) does **not** select the `reverted` column, and `models.ScenarioRun` (`internal/models/schema.go`) has no `Reverted` field at all. So the raw list exists, in the database, on every run — it just never reaches the frontend object the drawer already works with.

**A real gap found along the way, explicitly deferred to V2**: `revertFromSnapshot` only appends an item to its return list `if` the revert action itself succeeds (e.g. `if os.Remove(full) == nil { reverted = append(...) }`, `snapshot_windows.go:182-184`, and equivalently for registry/services/scheduled-tasks). A change that's detected but fails to revert (permission denied, file locked, etc.) is silently dropped — not recorded anywhere in the system, not just absent from the dashboard. This is arguably the most important case for a security report to show ("we found something and couldn't remove it"), but fixing it means changing `revertFromSnapshot`'s own recording behavior (or adding a non-destructive sibling), which is real, separate, agent-side work — not part of this V1.

## Architecture

### 1. `models.ScenarioRun` — new field

```go
// Reverted is one human-readable line per endpoint change the agent
// detected and successfully rolled back after the run (registry keys,
// services, scheduled tasks, temp files, hosts file, startup entries —
// see agent/snapshot_windows.go's captureSnapshot/revertFromSnapshot).
// Changes that were detected but failed to revert are NOT included here
// today — see docs/superpowers/specs/2026-08-06-endpoint-changes-tab-design.md.
Reverted []string `json:"reverted,omitempty"`
```

Added alongside the struct's other run-level fields (`internal/models/schema.go`) — not the `runRow` wrapper local to `ListScenarioRuns`'s handler, since `Reverted` is genuinely a stored, canonical run property (same category as `AlertsTotal`/`NoiseScore`), not a per-request-derived value like `DetectedTechs`.

### 2. `ListScenarioRuns` — expose the existing column

`internal/api/handlers.go:2201-2208`'s query gains `reverted` in the column list:

```go
rows, err := h.db.Query(r.Context(),
    `SELECT id, scenario_id, agent_id, name, status, results, score, initiated_by, started_at, completed_at,
            steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
            alerts_total, alerts_high_fidelity, noise_score, reverted
     FROM scenario_runs
     WHERE ($1 = '' OR agent_id = $1)
       AND ($2 = '' OR scenario_id = $2)
     ORDER BY started_at DESC LIMIT 100`,
    agentID, scenarioID,
)
```

The scan loop (`handlers.go:2227-2234`) gains a `var revertedRaw []byte` alongside the existing `resultsJSON, scoreRaw, detRaw`, scanned in the same `rows.Scan(...)` call. Unmarshaled the same way `scoreRaw` already is (`handlers.go:2239-2240`, `if len(scoreRaw) > 0 { json.Unmarshal(scoreRaw, &run.Score) }`) — **not** the same way as `resultsJSON`'s unconditional unmarshal a few lines above, which is safe there only because `results` is populated at row-creation time and never legitimately `NULL`. `reverted` can genuinely be `NULL` (a run from before this feature existed, or one that hasn't completed yet), and `json.Unmarshal(nil, ...)` on zero-length bytes errors ("unexpected end of JSON input") rather than silently producing an empty slice — so this needs the same `if len(revertedRaw) > 0 { json.Unmarshal(revertedRaw, &run.Reverted) }` guard `scoreRaw` already uses, not a bare unconditional call.

### 3. Frontend — render the tab

In `viewRunResults(run)` (`wwwroot/index.html`), replace the `soonPanel('Endpoint Changes')` call (`index.html:10953` as of this session's Timeline/MITRE work — re-verify the exact line before implementing, since it will drift again once those tabs' code is edited) with a real render function, following the exact framing already established in the PDF report (`pdf.go:1472-1489`) so the two surfaces tell a consistent story:

- If `run.reverted` is empty/absent: an honest empty state — *"No endpoint changes were captured for reversal during this run."*
- Otherwise: a summary line — *"The agent reverted N endpoint change(s) made during the run."* — followed by a plain bulleted list, one `x(item)`-escaped line per entry (matching this codebase's established discipline: agent-reported strings are attacker-adjacent data and must always go through the `x()` HTML-escaper, never raw into `innerHTML`, confirmed via the XSS-safety check already run for the Timeline/MITRE tabs this session).

No new backend endpoint, no new agent code, no new database column — every piece needed already exists except the one SQL projection and the render function.

## Non-goals (V1)

- **Changes that failed to revert** — invisible everywhere today (agent-side, not dashboard-side); real V2 work on `revertFromSnapshot`'s own recording behavior.
- **Per-step attribution** — the underlying system is whole-run only (`captureSnapshot(cmd.RunID)` once per run, not once per step); V1 matches that, doesn't invent finer granularity the data doesn't support.
- **Process-spawn tracking** — distinct from the persistence artifacts (services/scheduled tasks) already captured; not part of what already exists, so not part of V1.
- **Changing `revertFromSnapshot`'s revert behavior itself** — V1 only reads what it already writes; the revert-vs-report-only design question belongs to the V2 conversation, not this one.

## Testing

- `internal/api/list_scenario_runs_test.go` (existing file): a new test seeding a `scenario_runs` row with a non-empty `reverted` jsonb value, asserting `ListScenarioRuns`'s response includes the same items in `run.reverted`. A second case with `reverted` left `NULL` asserts the response succeeds with no error and the `reverted` field absent from the JSON entirely (the `omitempty` + nil-slice combination guarantees omission, not an empty-array placeholder — the test should assert on the field's absence specifically, not just "no error," to catch a future accidental change to non-omitempty semantics).
- A frontend check in the same style used for Timeline/MITRE this session: execute the actual render logic against both a populated and an empty `run.reverted`, asserting correct list rendering, correct empty-state text, and that a value containing HTML-special characters is properly escaped (not raw-injected into `innerHTML`).
