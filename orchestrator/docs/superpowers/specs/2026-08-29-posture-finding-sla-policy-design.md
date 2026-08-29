# Posture Finding SLA Policy — Design

**Status:** Sub-project B of the Posture/Compliance SLA initiative (Phase 9 of the
original Fleet Job Engine 10-phase proposal, [[project_endpoint_health_remediation]],
Sub-project 6, 2026-08-03). Builds directly on Sub-project A
(`2026-08-26-posture-finding-sla-foundation-design.md`, DONE, commits
`92d92a3`..`08215c2`), which shipped the persisted `posture_findings` table and its
automatic lifecycle.

## Goal

Give every open `posture_findings` row a **deadline**, and detect and announce the
moment that deadline is missed — the actual point of an SLA: someone finds out a
finding is overdue without having to go look. This sub-project adds policy
(severity→deadline mapping, admin-editable), per-finding-instance deadline tracking,
and active breach detection with notification. It does not touch remediation-job
linkage or fleet-wide reporting — those are Sub-projects C and D.

## Scope

**In scope:**
- `sla_policy` — the severity→duration mapping, admin-editable at runtime.
- `finding_slas` — one row per "open episode" of a `posture_findings` row, tracking
  that episode's deadline and outcome.
- A background tick that detects newly-breached episodes and emits a notification.
- Per-check severity, since `posture_findings.severity` is currently hardcoded to
  `'Medium'` for every finding (see below) — without this, a severity-keyed SLA
  policy is inert.
- Read/write API surface: policy CRUD (Admin-only write), SLA fields folded into
  Sub-project A's existing posture-finding endpoints, and a new fleet-wide
  currently-breached view.

**Explicitly out of scope**, deferred to named future sub-projects:
- **BAS-finding SLA** — still Phase 2 of the SLA initiative, untouched here.
- **Category-based policy differentiation** — policy keys on `severity` alone.
  `category` (Security Config vs Identity) remains available on `posture_findings`
  for filtering/reporting but plays no role in deadline calculation. Add
  category-specific overrides later only if a concrete requirement demands it (e.g.
  "High-severity Identity findings need a tighter deadline than High-severity
  Security Config findings") — no such requirement exists today.
- **Pre-breach "approaching deadline" warnings** — this sub-project only detects and
  notifies on an *actual* breach (`deadline_at` reached or passed). An early-warning
  tier (e.g. "80% of the window elapsed") is a plausible future addition, not built
  here.
- **SLA policy version history** — `sla_policy.updated_at`/`updated_by` is the only
  audit trail. No separate history/versioning table.
- **Remediation Job linkage / auto-escalation on breach** — Sub-project C's
  territory. A breach here only writes state and emits a notification; it never
  creates or touches a `jobs.Job`.
- **Fleet-wide reporting beyond the one breach list endpoint below** — deeper
  reporting (trends, SLA-compliance-rate-over-time, etc.) is Sub-project D.

## Background: the severity gap

`posture_finding_handlers.go`'s `applyPostureFinding` never sets `severity` on
`INSERT` — every posture finding today gets the column default, `'Medium'`,
regardless of which check it is. (The same underlying gap exists in a second,
unrelated consumer of the same static check metadata,
`endpointrisk_aggregations.go:193`'s `postureCheckInput`, which also hardcodes
`Severity: "Medium"` when building `endpointrisk.Finding` for the risk view — that
call site is not touched by this sub-project.)

Since this sub-project's policy keys exclusively on severity, shipping SLA without
fixing this would make every finding share one deadline — technically correct,
practically flat. `postureCheckFindingText` (`endpointrisk_aggregations.go:106`, the
static per-`check_id` metadata map already used for `Title`/`Description`/etc.) gains
one new field, `Severity string`, populated per check_id based on the check's actual
security impact:

| Severity | check_id |
|---|---|
| Critical | `linux-ssh-empty-passwords-forbidden`, `linux-no-empty-password-accounts` |
| High | `windows-firewall-enabled`, `windows-defender-realtime`, `windows-bitlocker-enabled`, `windows-smbv1-disabled`, `windows-rdp-nla-required`, `windows-local-admin-count`, `linux-firewall-enabled`, `linux-ssh-root-login-disabled` |
| Medium | `windows-guest-account-disabled`, `windows-password-min-length`, `windows-account-lockout-threshold`, `linux-apparmor-enabled`, `linux-password-min-length`, `windows-last-patch-age`, `linux-last-patch-age`, `linux-pending-security-updates` |
| Low | `windows-password-max-age`, `linux-password-max-age` |

Rationale: direct remote-exploitation, authentication-bypass, or disabled
malware/encryption defenses rank High/Critical; hardening/hygiene/defense-in-depth
controls rank Medium; long-window staleness checks with no specific known-exploitable
gap rank Low. `applyPostureFinding`'s `INSERT` sets `severity` from
`postureCheckFindingText[checkID].Severity` (falling back to `'Medium'` only if a
check_id is somehow missing from the map, which shouldn't happen for any in-scope
check).

## Data model

Two new tables, both scoped to `posture_findings` — no polymorphic
`finding_type`/`finding_id` reference, no schema readiness for BAS findings. When
BAS-finding SLA is actually needed (Phase 2), it gets its own schema designed around
the BAS finding lifecycle, not a generalized version of this one.

```sql
CREATE TABLE IF NOT EXISTS sla_policy (
    severity       text PRIMARY KEY,                 -- 'Critical' | 'High' | 'Medium' | 'Low'
    duration_hours int  NOT NULL CHECK (duration_hours > 0 AND duration_hours <= 8760),
    updated_at     timestamptz NOT NULL DEFAULT NOW(),
    updated_by     text NOT NULL DEFAULT ''
)
-- seeded via migration: Critical=24, High=72, Medium=168, Low=720

CREATE TABLE IF NOT EXISTS finding_slas (
    id                 text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    posture_finding_id text NOT NULL REFERENCES posture_findings(id),
    severity_at_start  text NOT NULL,   -- snapshot: a later postureCheckFindingText edit never rewrites history
    started_at         timestamptz NOT NULL,
    deadline_at        timestamptz NOT NULL,
    status             text NOT NULL DEFAULT 'active', -- active | breached | resolved
    breached_at        timestamptz,
    resolved_at        timestamptz
)
CREATE INDEX IF NOT EXISTS idx_finding_slas_posture_finding ON finding_slas (posture_finding_id)
CREATE INDEX IF NOT EXISTS idx_finding_slas_active_deadline ON finding_slas (status, deadline_at) WHERE status = 'active'
```

`finding_slas` is deliberately **one row per open episode**, not 1:1 with
`posture_findings`. A finding that's created, resolved (healed), then reopened months
later gets a fresh row with a fresh clock; its prior episode's row — breached or not —
stays exactly as history, untouched. This also means editing `sla_policy` only
changes the deadline calculation for *episodes started after the edit*: an existing
`finding_slas.deadline_at` is never recomputed, since it was captured once at
`started_at` using the policy in effect at that moment.

The `WHERE status = 'active'` partial index is both the tick's scan target and its
idempotency mechanism: once a row leaves `active` (→ `breached`), it drops out of
that index's match set, so a later tick cannot re-fire the same breach notification.

## Domain layer

New package `internal/slapolicy`, mirroring `internal/findings`' and
`internal/driftanalytics`' shape — pure functions, zero DB/network dependency, fully
unit-testable without a container:

```go
package slapolicy

type Policy struct {
    Severity      string
    DurationHours int
}

// DeadlineFor computes when a clock that started at startedAt expires, given the
// policy in effect for that severity at the moment it started.
func DeadlineFor(policy Policy, startedAt time.Time) time.Time {
    return startedAt.Add(time.Duration(policy.DurationHours) * time.Hour)
}

// EvaluateSLABreach is the single source of truth for "is this clock breached" --
// a deadline exactly reached counts as breached, not exclusively "after".
func EvaluateSLABreach(deadlineAt, now time.Time) bool {
    return !now.Before(deadlineAt)
}
```

That is the entire package. `internal/api` is the only caller.

## Orchestration

Three integration points, all in `internal/api`, no new packages beyond
`internal/slapolicy`:

**1. Write path — inside `applyPostureFinding`** (Sub-project A's existing function,
`posture_finding_handlers.go`), extending its existing transition switch:
- `tr == findings.Created` or `tr == findings.Reopened` → look up the `sla_policy`
  row matching the finding's (just-written) `severity` column, insert a new
  `finding_slas` row: `started_at = o.ObservedAt`, `deadline_at =
  slapolicy.DeadlineFor(policy, o.ObservedAt)`, `status = 'active'`,
  `severity_at_start` snapshotted from the same value.
- `tr == findings.Healed` → close the finding's current non-terminal `finding_slas`
  row (`status IN ('active','breached')` → `status = 'resolved'`, `resolved_at =
  NOW()`). Resolving out of `breached` is valid and expected — it's a late
  resolution, not an error; `breached_at` stays set so the episode's history shows it
  missed its window.

Severity is read from the finding's own `posture_findings.severity` column (written
once at row creation per the Background section above), not re-derived from
`postureCheckFindingText` at reopen time.

**2. Background tick — new `h.tickSLABreaches(ctx)`**, driven by a new
`exercise.NewPollScheduler(5 * time.Minute)` registered in `main.go` alongside the
existing schedulers (5 minutes matches `verifySyncScheduler`'s cadence; the shortest
policy duration, 24h, has no need for sub-5-minute detection precision):

```sql
SELECT id, posture_finding_id, deadline_at FROM finding_slas
 WHERE status = 'active' AND deadline_at <= NOW()
```

For each candidate row, confirm via `slapolicy.EvaluateSLABreach(deadlineAt, now)`
(keeping the actual breach decision in the one tested domain function, not
re-expressed as ad hoc SQL semantics), then `UPDATE finding_slas SET
status='breached', breached_at=NOW() WHERE id=$1`, then join to `posture_findings`
for `agent_id`/`check_id`/`title` and emit one `notifications.Event`.

**3. Notification** — new `notifications.EventSLABreached EventType = "sla_breached"`.
Severity maps: Critical→`SeverityCritical`, High→`SeverityError`,
Medium→`SeverityWarning`, Low→`SeverityInfo`. `AgentID` set from the joined
`posture_findings` row; `JobID` left empty (not job-related); `Metadata:
{findingId, checkId, severity, deadlineAt}`.

## API

Reusing this initiative's established permission split — read endpoints at
`CanExecuteRemediation` (Analyst+Admin, matching every other read endpoint in this
initiative), a fleet-wide-impacting write at `CanApproveRemediation` (Admin-only,
same rationale as maintenance-freeze and notification-webhook writes: a policy edit
can silently reshape deadlines across the whole fleet):

- `GET /api/sla/policies` — list the 4 severity rows. `CanExecuteRemediation`.
- `PATCH /api/sla/policies/{severity}` — body `{"durationHours": N}`. Validates
  `severity` is one of `Critical`/`High`/`Medium`/`Low` (404 otherwise) and
  `1 <= durationHours <= 8760` (400 otherwise). `CanApproveRemediation`.
- `GET /api/agents/{agentId}/posture-findings` *(extends Sub-project A's endpoint)* —
  adds `slaStatus`, `slaStartedAt`, `slaDeadlineAt`, `slaBreachedAt` (all null if the
  finding has no `finding_slas` row, e.g. pre-migration data) per finding. Permission
  unchanged.
- `GET /api/posture-findings/{id}` *(extends Sub-project A's endpoint)* — same SLA
  fields on the single-finding read. Permission unchanged.
- `GET /api/sla/breaches` — every currently-`breached` `finding_slas` row joined to
  its `posture_findings` row (`agentId`, `checkId`, `title`, `severity`,
  `category`), ordered `breached_at ASC` (oldest breach first). `CanExecuteRemediation`.

The two extended endpoints get their SLA fields via a `LEFT JOIN LATERAL` to each
finding's most recent `finding_slas` row (`ORDER BY started_at DESC LIMIT 1`) — this
also correctly surfaces a *resolved* episode's SLA outcome for a finding that isn't
currently open, since "most recent episode" doesn't require `status='active'`.

## Testing

Follows this initiative's established TDD pattern (real Postgres via testcontainers,
no mocks):

- `internal/slapolicy` — no container needed: `DeadlineFor` correctness;
  `EvaluateSLABreach` not-yet-due→false, exactly-at-deadline→true, past-due→true.
- `applyPostureFinding` extensions: Created inserts a `finding_slas` row with the
  policy-derived deadline; Reopened starts a new row, the prior episode's row is
  untouched; Healed resolves an `active` row; Healed also resolves a `breached` row
  (with `breached_at` preserved).
- `tickSLABreaches`: deadline not reached → no-op, no notification; deadline exactly
  reached → breach + notify; deadline passed → breach + notify; repeated ticks →
  exactly one notification per row (idempotency); multiple findings breaching in the
  same tick are all handled; an already-`resolved` row is never touched.
- Policy handlers: `GET` happy path; `PATCH` happy path; `PATCH` rejects an unknown
  severity (404) and a non-positive/absurd duration (400); `PATCH` is Admin-only
  (`TestRBACMatrix_AuthorizationBoundary`, not a direct-handler-call 403 test, per
  this initiative's established convention for router-middleware-only checks).
- Extended posture-finding endpoints carry the new SLA fields for both an
  active-episode finding and a resolved one.
- `/api/sla/breaches` returns only `breached` rows (excludes `active`/`resolved`),
  ordered oldest-breach-first.
- `TestRBACMatrix_NoDrift` gains the 3 new routes (2 SLA endpoints; the 2 extended
  endpoints are route-unchanged).

## Migration

Three additive statements in `orchestrator/internal/db/postgres.go`'s migration
list, same pattern as every other table added this initiative:
1. `CREATE TABLE IF NOT EXISTS` for `sla_policy` and `finding_slas`, plus indexes.
2. Seed `sla_policy`'s 4 default rows (`INSERT ... ON CONFLICT (severity) DO
   NOTHING`, so a re-run or an operator's prior edit is never clobbered).
3. Backfill: for every `posture_findings` row currently `status='open'` with no
   existing `finding_slas` row, insert one `active` episode starting `NOW()` (not
   the finding's original `first_seen` — that data predates this feature and
   backdating a deadline against it would let some findings arrive already
   breached, which is a migration artifact, not a real SLA miss).

Without step 3, a finding that was already open before this migration ran would only
gain SLA tracking on a future heal→reopen cycle (`Created`/`Reopened` are the only
transitions that start a clock) — for an open finding that never heals, that's an
indefinite gap, not a brief cold start. The backfill closes it: every open finding
gets a clock immediately, starting from the moment this feature deploys.
