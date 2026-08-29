# Posture Finding Remediation Telemetry — Design

**Status:** Sub-project C of the Posture/Compliance SLA initiative (Phase 9 of the
original Fleet Job Engine 10-phase proposal, [[project_endpoint_health_remediation]],
Sub-project 6, 2026-08-03). Builds directly on Sub-project A
(`2026-08-26-posture-finding-sla-foundation-design.md`, DONE, commits
`92d92a3`..`08215c2`) and Sub-project B
(`2026-08-29-posture-finding-sla-policy-design.md`, DONE, commits
`a31b52b`..`a8bfa88`).

## Goal

A `finding_slas` episode today only knows a deadline and whether it's been
breached — nothing about whether anyone is actually working the underlying
problem. This sub-project surfaces the most recent remediation attempt
(status, timestamps, whether it's currently in flight) alongside every SLA
finding, purely as read-only context. It does not change SLA state, breach
detection, or notification behavior in any way — a breaching finding still
breaches on schedule whether or not a remediation is running against it.

## Background: this needs no new schema

`remediation_requests` (Sub-project 4, `internal/remediation` +
`internal/api/remediation_query.go`) already carries everything needed:
`agent_id` and `check_id` columns directly (denormalized at request-creation
time from the remediation catalog's `CatalogEntry.CheckID`), a full status
lifecycle (`requested → dispatched → running → verifying →
completed/failed/verification_failed/timed_out/cancelled`, `remediation.
IsTerminal(status)` already classifies terminal vs. not), and per-stage
timestamps (`RequestedAt`/`DispatchedAt`/`ExecutionCompletedAt`/
`VerificationCompletedAt`/`CompletedAt`). This holds regardless of whether a
remediation was dispatched via the single-endpoint path (Sub-project 4) or a
batch `jobs.Job` (Sub-project 6) — both write to the same table.
`jobs.JobTarget` itself carries no `check_id` (only a `RefID` pointing at the
`remediation_requests.id` it created), so `remediation_requests` — not
`jobs.Job`/`JobTarget` — is the correct join target. This sub-project adds no
new table, no new column, and touches no existing write path.

## Scope

**In scope:** joining `finding_slas`/`posture_findings` to
`remediation_requests` by `(agent_id, check_id)`, scoped to the current open
episode, and surfacing the result on the existing SLA-aware read endpoints.

**Explicitly out of scope**, decided during brainstorming, not revisited
here:
- **Breach-clock suppression** — an in-flight remediation does not pause or
  delay `TickSLABreaches`. If the deadline passes while remediation is still
  running, the SLA is still breached; that's a real, meaningful signal, not
  an artifact to hide. `TickSLABreaches` is untouched by this sub-project.
- **Auto-triggering remediation from SLA state** — this sub-project is
  read-only surfacing only. Turning SLA creation into an enforcement trigger
  (auto-dispatching a Tier1 remediation the moment a finding opens) is a
  fundamentally different, much larger-authority feature, not attempted here.
- **`jobs.Job`/`JobTarget` visibility** (which batch job a remediation came
  from, its siblings) — `remediation_requests` alone answers everything this
  sub-project needs; batch-job context is a possible future addition, not
  built now.
- **Rollback status, `FixRunID`/`VerifyRunID` deep-links** — dropped from the
  projected fields; add later only if an actual need for them surfaces.
- **Any new write/mutation endpoint.**

## Data model

None. This sub-project is a read-time join over two already-shipped tables
(`finding_slas`, Sub-project B) and one pre-existing table
(`remediation_requests`, Sub-project 4). No migration.

## Query

For a given `finding_slas` episode (via its `posture_finding_id` →
`posture_findings.agent_id`/`check_id`, and the episode's own `started_at`):

```sql
SELECT id, remediation_id, tier, status, error,
       requested_at, dispatched_at, execution_completed_at,
       verification_completed_at, completed_at
  FROM remediation_requests
 WHERE agent_id = $1 AND check_id = $2 AND requested_at >= $3
 ORDER BY requested_at DESC, id DESC
 LIMIT 1
```

`$3` is the episode's `started_at`. This is a deliberate scoping decision: a
remediation attempt from a *prior, already-closed* episode never surfaces on
a reopened finding — a finding that heals, then reopens weeks later with
nothing yet attempted against the new occurrence, correctly shows no
remediation activity rather than a stale attempt that reads as "in progress"
for a problem that's actually new again.

Embedded in the two list-shaped read endpoints via a second
`LEFT JOIN LATERAL` (avoids one query per finding):

```sql
LEFT JOIN LATERAL (
    SELECT id, remediation_id, tier, status, error, requested_at, dispatched_at,
           execution_completed_at, verification_completed_at, completed_at
      FROM remediation_requests
     WHERE agent_id = pf.agent_id AND check_id = pf.check_id
       AND requested_at >= COALESCE(fs.started_at, '-infinity')
     ORDER BY requested_at DESC, id DESC LIMIT 1
) rr ON true
```

(`COALESCE(fs.started_at, '-infinity')` is a safe fallback for the
theoretical case of no `finding_slas` row at all — shouldn't occur post
Sub-project B, but the join degrades gracefully rather than excluding the
row entirely.)

## Read-model shape

Every existing response this sub-project touches (`scanPostureFindings`,
`GetSLABreaches`) is already `map[string]any`, not a typed Go struct — no
response type anywhere in this initiative's API layer uses one (Sub-project
A's spec: "mirrors `scanFindings`' existing map-based JSON, not a new Go
type"). `latestRemediation` follows the same convention: a small helper
function returning `map[string]any` (or `nil`), not a named struct —

```go
// buildLatestRemediation turns one rr.* row (all nullable -- a LEFT JOIN
// LATERAL ... ON true still yields exactly one row of NULLs when nothing
// matches) into the latestRemediation JSON object, or nil when nothing
// matched.
func buildLatestRemediation(id, remediationID, status, errText *string, tier *int,
	requestedAt, dispatchedAt, executionCompletedAt, verificationCompletedAt, completedAt *time.Time) map[string]any {
	if id == nil {
		return nil
	}
	m := map[string]any{
		"id": *id, "remediationId": *remediationID, "tier": *tier, "status": *status,
		"inProgress": !remediation.IsTerminal(*status), "requestedAt": *requestedAt,
	}
	if errText != nil && *errText != "" {
		m["error"] = *errText
	}
	if dispatchedAt != nil {
		m["dispatchedAt"] = *dispatchedAt
	}
	if executionCompletedAt != nil {
		m["executionCompletedAt"] = *executionCompletedAt
	}
	if verificationCompletedAt != nil {
		m["verificationCompletedAt"] = *verificationCompletedAt
	}
	if completedAt != nil {
		m["completedAt"] = *completedAt
	}
	return m
}
```

`inProgress` is `!remediation.IsTerminal(status)` — reusing the existing
function rather than re-deriving the terminal/non-terminal split. When no
remediation attempt exists in the episode's window, `latestRemediation` is
absent from the response entirely (the map has no such key), not an empty
object or `null` value.

## API

Extends 3 existing endpoints, all already `CanExecuteRemediation` — no new
routes, no new permission:

- `GET /api/agents/{agentId}/posture-findings` (list) — `latestRemediation`
  via the `LEFT JOIN LATERAL` above. **Does not** call
  `reapTimedOutRemediation`.
- `GET /api/sla/breaches` (list) — same join, same no-reap choice.
- `GET /api/posture-findings/{id}` (single) — same join, **and** calls the
  existing `reapTimedOutRemediation` (`remediation_query.go:39`) on the
  resulting `latestRemediation` before responding.

The reap/no-reap split isn't arbitrary — it matches this codebase's own
existing precedent exactly: `GetRemediation` (single-record read) already
calls `reapTimedOutRemediation`; `ListAgentRemediations` (list read)
deliberately does not, avoiding a write on every list poll. This sub-project
follows the same rule rather than introducing a new one.

## Testing

TDD, testcontainers, matching Sub-projects A and B's established pattern:
- No remediation attempt in the episode → `latestRemediation` absent
- One attempt within the episode window → surfaced correctly, every field
  matches
- Multiple attempts → newest by `requested_at` wins, `id` as tie-breaker
- An attempt from a prior, already-closed episode with nothing yet in the
  current one → not surfaced (the `started_at` filter's core case)
- `InProgress` true for each non-terminal status, false for each terminal
  status (`remediation.IsTerminal`'s own 5 terminal values)
- `GetPostureFinding` corrects a stale `dispatched`/`running`/`verifying`
  row past its deadline to `timed_out` before responding
- `ListAgentPostureFindings` and `GetSLABreaches` do **not** apply that
  correction — an explicit test for this deliberate asymmetry, since it's
  easy for a future change to "fix" by accident

## Migration

None — no schema change.
