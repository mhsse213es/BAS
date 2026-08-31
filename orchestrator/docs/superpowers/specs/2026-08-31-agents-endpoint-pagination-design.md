# Agents Endpoint Pagination — Design

## Context

Today's load testing ([[project_load_perf_scale_testing]]) found that `GET
/api/agents` (`orchestrator/internal/api/handlers.go:677`, `GetAgents`)
degrades badly as the agent fleet grows:

1. **Fixed already** (commit `9a61a64`): the `sims` column was computed via a
   correlated subquery re-executed once per row. Rewritten as a single
   `LEFT JOIN (... GROUP BY agent_id)`.
2. **Not yet fixed — this spec**: even with (1) fixed, a real k6 run against
   the staging server showed a single unpaginated call returning ~2,500 agent
   rows costs **1,081,960 bytes (~1.08MB)** of uncompressed JSON, and took
   **~1.74s to transfer** on top of an 8ms query (confirmed via `curl -w`
   timing breakdown: `time_starttransfer=0.272s`, `time_total=2.01s`). Payload
   size — and therefore transfer time — grows linearly with fleet size
   regardless of query speed. At current per-row size (~430 bytes
   uncompressed), a 10,000-agent fleet means a ~4.3MB response on every
   dashboard load.

This spec covers adding real pagination to `GetAgents`, migrating the one
frontend consumer that actually needs it, and preserving correctness for
everything currently computed from having the full list in memory (KPI
tiles, toolbar bucket counts, status/search filtering).

## Non-goals

- **The other 8 `/api/agents` call sites** in `wwwroot/index.html` (lines
  5111, 7463, 16982, 18503, 19267, 20174, 21022, 21078 as of this writing —
  re-grep `apicall\('/api/agents'\)|fetch\('/api/agents'` if this drifts)
  are untouched. They're dashboards, group pickers, and report
  agent-selectors that either need the full list for aggregate
  computation or are working with small enough result sets that
  pagination adds complexity with no benefit. Only `loadAgents()`
  (`wwwroot/index.html:8123`, backing the System Tree table) migrates.
- **No page-number UI.** Keyset pagination doesn't support jumping to
  page N; the frontend gets a "Load more" affordance, not numbered pages.
- **No response compression as an alternative.** Gzip was considered and
  rejected as a substitute for pagination (see prior design discussion) —
  it would cut transfer size but not fix the underlying "ship the whole
  fleet on every load" problem, which only gets worse over time.

## Backend Design

### Response contract — conditional on query params

`GetAgents` returns its **existing bare JSON array**, completely unchanged,
when neither `limit` nor `cursor` is present in the query string — this is
what keeps the other 8 call sites working with zero changes.

When either `limit` or `cursor` is present, it returns:

```json
{
  "items": [ /* []models.Agent, same shape as today's array elements */ ],
  "next_cursor": "opaque-base64-string",
  "has_more": true,
  "totals": { "online": 412, "degraded": 3, "offline": 9, "retired": 21 }
}
```

`next_cursor` is omitted (or `""`) when `has_more` is `false`.

### Keyset pagination

Sort stays `ORDER BY a.last_update DESC, a.agent_id DESC` (matches today's
`ORDER BY a.last_update DESC`, with `agent_id` added purely as a tiebreaker
for rows sharing the same `last_update` timestamp — ties are possible since
many agents can heartbeat in the same wall-clock second).

**Why not offset/limit:** `last_update` changes on every heartbeat (every
30s by default). With `LIMIT/OFFSET`, an agent that heartbeats between two
page requests can shift position in the sort order, causing the next
`OFFSET`-based page to skip rows that moved earlier, or re-show rows that
moved later. At a 30-second heartbeat interval this is not a rare edge case
— it will happen on essentially every multi-page traversal that takes more
than a few seconds.

**Cursor contents** (JSON, base64-encoded, opaque to the frontend):
```json
{"snapshot": "2026-08-31T17:00:00.123Z", "last_update": "2026-08-31T16:59:58.001Z", "agent_id": "loadgen-000042"}
```

- `snapshot`: captured server-side as `time.Now()` on the **first** page
  request (no incoming cursor) and carried forward unchanged in every
  subsequent page's cursor. Every page's query filters `a.last_update <=
  snapshot` — so an agent that updates *after* the traversal started
  cannot reorder into an already-returned page, get duplicated, or get
  silently dropped by moving across a page boundary. It simply won't be
  reflected until the next fresh traversal (page 1 with no cursor).
- `last_update`/`agent_id`: the sort-key values of the **last row actually
  returned** on the previous page. The next page's query adds:
  ```sql
  AND (a.last_update, a.agent_id) < ($last_update, $agent_id)
  ```

**Query shape** (paginated path — replaces the unconditional query only
when `limit`/`cursor` present; the existing unpaginated query at
`handlers.go:678-707` is untouched for the no-params case):

```sql
SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
        COALESCE(sr.sims, 0) AS sims,
        a.stopped_by, COALESCE(u.username, a.stopped_by), a.stopped_at, a.stop_reason,
        a.group_id, g.name, a.uninstall_error, a.uninstall_error_at, a.uninstall_requested_at
 FROM agents a
 LEFT JOIN users u ON u.id = a.stopped_by
 LEFT JOIN agent_groups g ON g.id = a.group_id
 LEFT JOIN (SELECT agent_id, COUNT(*) AS sims FROM scenario_runs GROUP BY agent_id) sr ON sr.agent_id = a.agent_id
 WHERE a.last_update <= $1                                    -- snapshot, always present
   [AND a.group_id IN (<existing recursive CTE>)]              -- if groupId param, unchanged from today
   [AND (a.last_update, a.agent_id) < ($2, $3)]                -- if cursor carries a prior position (page 2+)
   [AND (a.hostname ILIKE $n OR a.agent_id ILIKE $n            -- if q param present
         OR a.ip_address ILIKE $n OR g.name ILIKE $n)]
   [AND <bucket CASE expression, see below> = $n]              -- if bucket param present, not 'all'
 ORDER BY a.last_update DESC, a.agent_id DESC
 LIMIT $n+1                                                     -- fetch one extra row to derive has_more
```

Fetch `limit+1` rows. If exactly `limit+1` came back, `has_more = true` and
the extra (probe) row is dropped before building the response — `next_cursor`
is built from the **last of the `limit` returned rows**, not the probe row.
If `limit` or fewer came back, `has_more = false` and `next_cursor` is empty.

### Bucket expression — reused for filtering AND totals

`agentBucket()` (`wwwroot/index.html:7939-7944`) and
`models.EffectiveAgentStatus` (`internal/models/schema.go:344-349`, a 90s —
`AgentOfflineAfter` — staleness check) together define: retired if
`state IN ('retired','uninstalled')`; else offline if stale past 90s; else
degraded if `state != 'active'`; else online. This is simple enough to
express once in SQL and reuse in both places it's needed, avoiding a second
Go/SQL implementation of the same rule to keep in sync:

```sql
CASE
  WHEN COALESCE(a.state,'active') IN ('retired','uninstalled') THEN 'retired'
  WHEN (NOW() - a.last_update) > INTERVAL '90 seconds' THEN 'offline'
  WHEN COALESCE(a.state,'active') != 'active' THEN 'degraded'
  ELSE 'online'
END
```

Define this once as a Go string constant (e.g. `agentBucketCaseSQL` in
`handlers.go`) and interpolate it into both the row-list query's optional
`WHERE ... = $bucket` clause and the totals query below — never write it out
twice.

### `totals` — a second, narrow query

```sql
SELECT <bucket CASE expression> AS bucket, COUNT(*)
FROM agents a
[WHERE a.group_id IN (<same recursive CTE, if groupId param>)]
GROUP BY bucket
```

Scoped by `groupId` (matching what the tiles show today — group-filtered,
not search-filtered: `agent-search`'s `oninput` only calls
`renderAgentRows()` today, never `renderAgentTiles()`, so search text has
never affected the tile counts — this design preserves that). **Not**
scoped by `q` or `bucket` — the tiles must always reflect the true
fleet-wide (or group-wide) counts, independent of whatever filter/search is
currently narrowing the visible row list, exactly as they do today.

### Query params — full list (paginated path only)

| Param | Meaning | Default |
|---|---|---|
| `limit` | Page size | `100` if unset but `cursor` present; presence of either triggers pagination |
| `cursor` | Opaque token from a prior response's `next_cursor` | none (first page) |
| `groupId` | Existing recursive-descendant group filter | none (unchanged from today) |
| `q` | Substring match on hostname / agent_id / ip_address / group name | none |
| `bucket` | `online`\|`degraded`\|`offline`\|`retired`\|`all` | `all` |

`limit` is clamped server-side to `[1, 500]` (silently clamped, not
rejected — a caller passing `limit=10000` just gets 500).

### Error handling

A `cursor` that fails base64 decode or JSON unmarshal returns `400` with
`{"error": "invalid cursor"}` — same `jsonError` helper already used
throughout `handlers.go`. This is the one new failure mode pagination
introduces (an unpaginated call can't hit it, since it never touches the
cursor path).

## Frontend Design

Only `orchestrator/wwwroot/index.html`'s System Tree view changes.

### `loadAgents()` (currently `wwwroot/index.html:8123-8129`)

Rewritten to call `/api/agents` with `limit=100` (plus `groupId` if a group
is selected), storing the response's `items` into the existing `agents`
array (replacing it on a fresh load — group change, initial load, or an
explicit refresh — rather than appending), and storing `next_cursor`/
`has_more` in new module-level state (`agentsNextCursor`,
`agentsHasMore`).

A "Load more" control appears below the table when `agentsHasMore` is true;
clicking it re-calls `/api/agents` with the stored cursor and **appends**
the returned `items` to the existing `agents` array (not a replace), then
re-renders.

### Tiles and toolbar counts

`renderAgentTiles()` (`wwwroot/index.html:8130-8143`) and the count badges
inside `renderAgentToolbar()` (`wwwroot/index.html:8144-8153`) stop scanning
`agents.length`/`agents.filter(...)` and instead read the new `totals`
field returned alongside `items` — stored in a new module-level
`agentTotals` object, updated on every `loadAgents()` call (fresh load,
group change) but **not** touched by "Load more" (appending more rows to
`agents` doesn't change the true fleet-wide totals, which were already
correct from the first page's response).

### Search (`agent-search` input, `wwwroot/index.html:1781-1783` post
System-Tree-tab move)

`oninput` changes from `renderAgentRows()` (client-side filter of the
already-loaded `agents` array) to a debounced (~300ms) re-fetch of page 1
with `q=<value>` — replacing `agents` with the new result set, resetting
`agentsNextCursor`/`agentsHasMore`. Clearing the search box re-fetches page
1 with no `q`.

### Status bucket toolbar (`AGENT_FILTER`, `setAgentFilter`,
`wwwroot/index.html:8154`)

Changes from a pure client-side `agents.filter(...)` (in `renderAgentRows`)
to also passing `bucket=<value>` on re-fetch of page 1, same pattern as
search — clicking "Offline" re-fetches page 1 scoped to offline agents
fleet-wide, not just filtering whatever's currently loaded.

### `renderAgentRows()` (`wwwroot/index.html:8155+`)

Simplifies: since the server now does bucket filtering, this function no
longer needs its own `AGENT_FILTER` client-side filter — it renders
whatever is currently in `agents` (already scoped by the server). Search
highlighting (if any exists today) is out of scope for this change unless
already present.

## Testing

- **Backend**: new tests in `orchestrator/internal/api/agent_lifecycle_test.go`
  (alongside the existing `TestGetAgents_*` tests and the `sims` regression
  test from commit `9a61a64`):
  - Unpaginated call (no `limit`/`cursor`) still returns a bare array,
    unchanged shape — regression guard against ever breaking the other 8
    consumers.
  - Paginated call with `limit=2` against 5 seeded agents returns exactly 2
    items, `has_more=true`, a non-empty `next_cursor`.
  - Following `next_cursor` returns the next 2, then the last 1 with
    `has_more=false`.
  - An agent's `last_update` changing (simulating a heartbeat) *between*
    page 1 and page 2 of a traversal does not cause a duplicate or a skip —
    the snapshot boundary holds. This is the test that actually proves the
    design decision was necessary.
  - `totals` matches manually-seeded bucket counts (one agent per bucket:
    online, degraded via non-active state, offline via a `last_update` >90s
    in the past, retired via state).
  - `bucket=offline` on the row query returns only the offline-seeded agent.
  - `q=` substring matches hostname, agent_id, and group name.
- **Frontend**: extract the inline `<script>` and `node --check` it
  (this session's established syntax-check method) after the rewrite.
  Attempt a real browser walkthrough if a dev environment can reasonably be
  spun up — load the System Tree tab, confirm tiles show correct fleet-wide
  totals, click "Load more", search, and click through the status buttons —
  and say plainly if that wasn't feasible rather than claiming untested
  work is verified.

## Verifying the fix

Once deployed, re-run the same `curl -w` timing check used to find this
problem, and re-run the same load-test stages
(`orchestrator/loadtest/runbook.sh`) used to measure the original
degradation, to get a real before/after number for
`docs/load-testing-capacity-report.md` — this was the whole reason this
work was picked up. Expect the paginated response to be a small, page-size-bound
document that returns in a small number of milliseconds' worth of transfer
time regardless of total fleet size.
