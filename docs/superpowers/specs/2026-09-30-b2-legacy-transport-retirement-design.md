# B2 Legacy Transport Retirement — Design

## Context

The B1/B3/B4 agent trust model spec
(`docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md`)
shipped mTLS as the primary agent transport, keeping the plaintext/shared-secret
`:9000` listener alive as a temporary migration bridge. That spec explicitly
deferred designing its removal (line 31): *"B2 (removing the legacy
plaintext/shared-secret listener entirely) — deferred until the existing
fleet has actually migrated to mTLS... does not design its removal."*

As of 2026-09-30 the following invariants already exist in shipped code —
this design does not touch or re-decide any of them:

- An already-enrolled identity never falls back to legacy transport, only
  retries mTLS (`agent/bootstrap.go:32`, gated by `isEnrolled()`).
- The dashboard already shows a per-agent, point-in-time "⚠ Legacy
  transport" badge (this does not by itself answer "is it now safe to
  retire `:9000`" — that needs a historical/aggregate view, which is what
  this design builds).
- `:9000`'s handler is `WithLegacyListenerTag(router)` — the **same full
  router** every other listener uses, not a restricted one
  (`orchestrator/cmd/server/main.go:948-950`). It exposes the entire API
  surface (dashboard statics, `/health`, admin endpoints, etc.), not just
  agent-protocol endpoints. This matters directly for what counts as
  "legacy agent activity" below.
- `WithLegacyListenerTag` / `isLegacyListener(r)` already exist
  (`orchestrator/internal/api/observability.go:83-92`) as the exact hook
  point this design uses — this is additive, not a new instrumentation
  layer.

What does not exist: any measurable evidence of when migration is actually
complete. Today "retire `:9000`" is a judgment call with no instrument
behind it. This design builds that instrument — not the actual retirement
of `:9000` or deletion of its code paths, which stays future, separately
scoped work (see Non-goals).

## Goals

1. Prove, with real fleet data, when zero agents have used legacy
   transport for a defined observation window — not a guess.
2. Never produce a false "clear" — undercounting legacy usage in a way
   that lets `:9000` retire while something still depends on it is the
   one failure mode this design must not have, even at the cost of some
   over-conservatism.
3. Give an operator an auditable trail (which agents, when, evidence) to
   review before manually acting on the eligibility signal.

## Non-goals

- Actually disabling or deleting the `:9000` listener's code. This design
  adds a config flag operators can set (Step 5 of the retirement
  procedure below); flipping it is a manual operator action informed by
  this design's evidence, not something this design triggers itself.
- Deleting the `agentSecret` fallback, the agent's legacy dial path, or
  any other legacy code. That is explicitly separate, later-scoped work,
  same as the parent B1/B3/B4 spec already deferred it.
- Redesigning the existing per-agent "Legacy transport" badge — it stays
  as-is; this design adds a new, separate historical/fleet view.

## Population semantics

An agent counts as having used legacy transport on a given UTC calendar
day if **any** request that day, on the `:9000` listener, matched the
legacy agent-protocol route allowlist below and was handled successfully.
This is the broadest, most conservative definition: an agent that touched
`:9000` even once during the observation window is not yet migrated,
regardless of whether it also successfully uses mTLS elsewhere.

### Legacy agent-protocol route allowlist

Verified against `orchestrator/internal/api/routes.go:79-93` (the existing
`// Agent endpoints — protected by optional AGENT_SECRET shared token`
block) plus the `/ws/agent` WebSocket upgrade endpoint immediately after
it (line 97). This is the exact and only set of routes that count —
**not** a blind "any 2xx on `:9000`" rule, since `:9000` also serves
`/health`, dashboard statics, and admin endpoints that say nothing about
agent dependency:

```
POST /api/agents/enroll
POST /api/agents/enroll-csr
POST /api/agents/unenroll
POST /api/agents/{agentId}/uninstall-result
POST /api/agents/events
POST /api/heartbeat
POST /api/scenarios/result
POST /api/scenarios/events
POST /api/scenarios/runs/{runId}/detections
POST /api/attackpath/collect
POST /api/attackpath/sharphound
POST /api/attackpath/jobs/{id}/ack
GET  /ws/agent
GET  /api/agents/ping
```

"Successfully handled" means the response status is 2xx **and** the route
matched one of the above (matched via chi's `RouteContext(r.Context()).RoutePattern()`,
the same mechanism `RequestLoggingMiddleware` already uses — no new
routing logic needed). A 4xx/5xx on a legacy-protocol route (e.g. a
rejected/malformed heartbeat) is not logged as usage — it didn't actually
depend on the listener being available in a way retirement would break.

## Data model

Two tables, both written by the same instrumentation point:

```sql
CREATE TABLE legacy_transport_log (
    agent_id     TEXT        NOT NULL,
    day          DATE        NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    endpoint     TEXT        NOT NULL,  -- last-seen route pattern that day, audit only
    UNIQUE (agent_id, day)
);
CREATE INDEX idx_legacy_transport_log_day ON legacy_transport_log (day);

CREATE TABLE legacy_transport_unattributed (
    day          DATE        NOT NULL PRIMARY KEY,
    last_seen_at TIMESTAMPTZ NOT NULL,
    request_count INT        NOT NULL DEFAULT 1
);
```

One row per agent per day (upsert on `(agent_id, day)`), not one row per
request — a heartbeating-every-30s agent would otherwise produce ~2,880
rows/day/agent for no benefit; the retirement decision only ever needs
"did this agent touch legacy today," never a full request-level log.

**Unattributed legacy traffic is tracked separately, not discarded.**
A legacy-protocol request that cannot be resolved to an `agent_id` (see
Attribution below) still represents real, unexplained legacy dependency —
silently dropping it would let it disappear from the eligibility
calculation entirely, producing exactly the false-clear this design
exists to prevent. It gets its own table rather than an `agent_id = NULL`
row in `legacy_transport_log`, because PostgreSQL's NULL uniqueness
semantics don't enforce "one row per day" the way `UNIQUE (agent_id, day)`
does for real agent IDs — a dedicated table with `day` as its own primary
key gets the same one-row-per-day guarantee cleanly.

**Atomic, order-safe upsert** (protects against an older, delayed request
arriving after a newer one and moving `last_seen_at` backwards):

```sql
INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint)
VALUES ($1, $2, $3, $4)
ON CONFLICT (agent_id, day) DO UPDATE
  SET last_seen_at = GREATEST(legacy_transport_log.last_seen_at, EXCLUDED.last_seen_at),
      endpoint      = CASE WHEN EXCLUDED.last_seen_at > legacy_transport_log.last_seen_at
                            THEN EXCLUDED.endpoint ELSE legacy_transport_log.endpoint END;
```

```sql
INSERT INTO legacy_transport_unattributed (day, last_seen_at, request_count)
VALUES ($1, $2, 1)
ON CONFLICT (day) DO UPDATE
  SET last_seen_at   = GREATEST(legacy_transport_unattributed.last_seen_at, EXCLUDED.last_seen_at),
      request_count  = legacy_transport_unattributed.request_count + 1;
```

## Attribution

For each allowlisted route, `agent_id` is read from whichever field that
endpoint's request actually carries it in:

- Query param `agentId` (e.g. `/ws/agent`, `/api/agents/ping`)
- JSON body field `AgentID`/`agent_id` (e.g. `/api/heartbeat`,
  `/api/scenarios/result`) — parsed the same way each handler already
  parses its own request body; this instrumentation reads the
  already-decoded value from context (handlers already have it), not a
  second body parse.
- Path param `{agentId}` (e.g. `/api/agents/{agentId}/uninstall-result`)
- `/api/agents/enroll-csr`: the CSR's claimed subject/agent identity
  (same value `EnrollCSR`'s handler already extracts for its own logic)

If a matched, successful legacy-protocol request genuinely carries none of
these (shouldn't happen for any route in the allowlist given each already
needs agent identity for its own handler logic to work at all — this is a
defensive fallback, not an expected path), it logs to
`legacy_transport_unattributed` instead of being dropped.

## Eligibility computation

Two queries, run on demand (no background job needed — cheap enough to
compute at request time given the tables' small size):

```sql
-- Fleet-wide gate: the actual 30-day rule
SELECT GREATEST(
  (SELECT MAX(last_seen_at) FROM legacy_transport_log),
  (SELECT MAX(last_seen_at) FROM legacy_transport_unattributed)
) AS last_legacy_seen_at;
```

- `last_legacy_seen_at IS NULL` → eligible (no legacy traffic ever
  recorded)
- `NOW() - last_legacy_seen_at >= 30 days` → eligible
- otherwise → not eligible

This is deliberately based on the single latest event timestamp
fleet-wide, not a `day >= NOW() - 30 days` range query — a date-bucket
range query can treat a partially-covered current day as satisfying the
window and is one off-by-one away from being wrong. A single `MAX()`
comparison has no such ambiguity: eligibility is exactly "no successful
legacy request anywhere in the fleet, including unattributed, for 30
consecutive days."

```sql
-- Per-agent breakdown, for the blocking-agent list
SELECT agent_id, MAX(last_seen_at) AS last_seen
FROM legacy_transport_log
GROUP BY agent_id
ORDER BY last_seen DESC;
```

## API & dashboard surface

New endpoint: `GET /api/agents/legacy-migration-status` (authenticated,
same JWT-protected group as `/api/agents`), returning:

```json
{
  "eligible": false,
  "lastLegacySeenAt": "2026-09-27T14:32:10Z",
  "daysClean": 3,
  "daysRequired": 30,
  "blockingAgents": [
    {"agentId": "f02cab730e91febd", "hostname": "DESKTOP-5TVEBSI", "lastSeen": "2026-09-27T14:32:10Z"}
  ],
  "unattributedRequests": {"lastSeen": "2026-09-25T09:00:00Z", "count": 3}
}
```

Dashboard: a new panel on the Agents page (not a modification of the
existing per-agent badge), showing the days-clean counter, the
blocking-agent list (resolved to hostname via the existing agents table),
and the unattributed-traffic count with an explicit "retirement blocked
by unattributed traffic" state distinct from "blocked by agent X" — an
operator needs to know these are different problems requiring different
follow-up (re-enroll an agent vs. investigate an unknown caller).

## Retirement procedure

This is an explicit operational sequence, not a bare config check:

1. Fleet reaches 30 consecutive clean days (per the eligibility query
   above). Dashboard status changes to `ELIGIBLE_FOR_REVIEW`.
2. Operator reviews the blocking-agent history and unattributed-traffic
   audit trail via the dashboard panel / API endpoint.
3. Operator sets `BAS_LEGACY_LISTENER_ENABLED=false` in `.env`.
4. Restart/redeploy the orchestrator. `main.go` checks this flag
   immediately before `legacySrv.ListenAndServe()` — when false, the
   goroutine that would start it returns immediately instead, and this
   is logged at startup (`"[*] Legacy listener disabled via
   BAS_LEGACY_LISTENER_ENABLED=false"`) so it's visible in the startup
   log the same way every other listener's bind is.
5. Operator verifies `:9000` is no longer listening (`ss -ltnp` or
   equivalent — same verification technique used live tonight during the
   staging incident this design grew out of).
6. The retirement action itself (config change + timestamp) is recorded
   in the existing audit-log mechanism this codebase already uses for
   other admin actions (`h.auditLogAs`, see `handlers.go`'s `Login` for
   the existing pattern) — so "when was `:9000` actually turned off, and
   by whom" is itself auditable, not just the evidence leading up to it.

**Race guard:** the eligibility calculation and the listener's actual
shutdown are not atomic — a legacy request can arrive after step 1's
`ELIGIBLE_FOR_REVIEW` status is computed but before step 4's restart
completes. This is why eligibility is computed live from `MAX(last_seen_at)`
at query time (not cached/frozen at the moment it first became eligible):
any such request immediately updates `last_legacy_seen_at`, and the very
next eligibility check correctly reports not-eligible again, resetting the
30-day clock. An operator who checks the panel again before restarting —
which step 2's review already requires — cannot miss this: a request in
that gap makes the panel show "not eligible" again before they get to
step 3.

## Out of scope for this design (future, separately-scoped work)

- Actually deleting `:9000`'s listener setup, the `agentSecret`
  query/header fallback, and the agent's legacy dial code, once the
  disabled state (`BAS_LEGACY_LISTENER_ENABLED=false`) has itself proven
  stable for some operator-judged period. This design's retirement
  procedure stops at Step 6 (disable + audit) on purpose — matching the
  phased "disable first, delete later" decision made during this design's
  review.
- Any change to the existing per-agent "Legacy transport" badge.
- Any change to `enrollSrv` (`:9444`) — that listener is explicitly
  permanent infrastructure per the parent spec, not part of this
  retirement.
