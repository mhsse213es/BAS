# Posture Finding SLA Foundation — Design

**Status:** Sub-project A of the Posture/Compliance SLA initiative (Phase 9 of the
original Fleet Job Engine 10-phase proposal, [[project_endpoint_health_remediation]],
Sub-project 6, 2026-08-03).

## Goal

Give posture/compliance findings (CIS-benchmark Security Configuration and Identity
checks) a **persisted, stateful lifecycle** — first-failed/recurred/healed/reopened,
with historical continuity — so a later sub-project can attach SLA deadlines to
something durable. Today `internal/endpointrisk.Finding` is recomputed from scratch
on every read and has no memory of when a check first started failing, whether it
was previously resolved, or how many times it has recurred. No SLA design can answer
"how long has this been open" against a value that doesn't persist between reads.

This sub-project does **not** add SLA policies, deadlines, or breach detection —
that's Sub-project B, built on top of what this ships. It does not touch Application
Risk or Compliance-framework findings, or the existing BAS `findings` table/lifecycle
— see Scope below.

## Background: two pre-existing finding universes

This codebase already has two unrelated "finding" concepts, and this design
deliberately does not unify them:

1. **BAS findings** (`internal/findings` package + `findings` table) — persisted,
   stateful, keyed `(agent_id, technique_id, control_class)`, driven by
   attack-simulation outcomes (prevented/missed/detected_only) from `scenario_runs`.
   Has a proven, tested state machine (`findings.Apply`) already handling exactly the
   PASS→FAIL/FAIL→FAIL/FAIL→PASS transition logic this sub-project needs.
2. **Posture/compliance findings** (`internal/endpointrisk.Finding`) — computed fresh
   on every read from the latest `scenario_runs.results` per `check_id`, no
   persistence, no lifecycle. This is the domain the rest of the Endpoint Health &
   Remediation initiative (Jobs, Remediation, Drift Analytics) already operates on.

This sub-project builds a **second, independent persisted table** (`posture_findings`)
for the posture domain, reusing `findings.Apply` — the pure state-machine function —
as a shared library call, not merging the two tables or their status vocabularies.
`findings.Apply(s State, o Observation) (State, Transition)` takes a domain-agnostic
`Observation{Outcome, RunID, ObservedAt}` and already contains the out-of-order guard,
same-run refinement, and recur/heal/reopen logic — there is no reason to re-derive
that logic a second time.

## Scope

**In scope**, this sub-project only:
- Security Configuration and Identity category checks
  (`endpointrisk.CategorySecurityConfig` = `"security-configuration"`,
  `endpointrisk.CategoryIdentity` = `"identity"`) — the checks that are cleanly
  identified by `(agent_id, check_id)` alone, one finding per check per agent.
- A new `posture_findings` table and ingest path that keeps it in sync with every
  scenario run's results.
- Read-only API endpoints so later sub-projects (and manual QA) can query it.

**Explicitly out of scope**, deferred to named future sub-projects:
- **Application Risk findings** (EOL/outdated software) — a single `check_id`
  produces multiple findings per agent (one per catalog entry), so `(agent_id,
  check_id)` cannot uniquely identify them. Needs its own identity design
  (`catalog_entry_id`-based) before it can join this lifecycle. Not solved here,
  and this design does not widen the key to accommodate it speculatively.
- **Compliance-framework findings** — don't currently populate a stable `ID` at all.
  Needs its own persisted-identity design first.
- **SLA policy, deadlines, breach detection** (`sla_policy`, `finding_slas` tables)
  — Sub-project B, sits on top of `posture_findings.id`.
- **Remediation Job linkage** (ack/first-remediation-attempt timestamps) —
  Sub-project C.
- **Reporting** — Sub-project D.
- **Operator triage/risk-accept workflow** (an equivalent to BAS findings'
  `SetFindingStatus`, open/triaged/remediated/risk_accepted) — not requested for
  this round. `posture_findings.status` only ever takes the two values the
  automatic lifecycle itself produces (`open`, `remediated`); no manual-override
  endpoint ships in this sub-project. Flag during spec review if this is wanted now.
- **BAS-finding SLA** — a separate future sub-project (Phase 2 of the SLA
  initiative), reusing this same pattern against the *existing* `findings` table.

## Data model

New table, deliberately mirroring the existing `findings` table's shape (same
column names/semantics where the concept overlaps, so the two tables read the same
way to anyone already familiar with `findings`):

```sql
CREATE TABLE IF NOT EXISTS posture_findings (
    id                text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    agent_id          text NOT NULL,
    check_id          text NOT NULL,
    category          text NOT NULL DEFAULT '', -- endpointrisk.CategorySecurityConfig | CategoryIdentity
    title             text NOT NULL DEFAULT '', -- postureCheckFindingText[check_id].Title, snapshotted at creation
    severity          text NOT NULL DEFAULT 'Medium', -- matches postureCheckInput's current hardcoded value; not computed per-check today
    exposure_state    text NOT NULL DEFAULT 'missed', -- always "missed" for this domain (no detection-vs-prevention distinction like BAS); column kept for findings.Apply/Observation compatibility
    status            text NOT NULL DEFAULT 'open', -- open | remediated (automatic only, see Scope)
    occurrence_count  int NOT NULL DEFAULT 1,
    reopened_count    int NOT NULL DEFAULT 0,
    last_run_id       text,
    first_seen        timestamptz NOT NULL DEFAULT NOW(),
    last_seen         timestamptz NOT NULL DEFAULT NOW(),
    last_observed_at  timestamptz NOT NULL DEFAULT NOW(),
    resolved_at       timestamptz,
    resolved_reason   text,
    created_at        timestamptz NOT NULL DEFAULT NOW(),
    tenant_id         text NOT NULL DEFAULT 'default',
    CONSTRAINT uq_posture_finding UNIQUE (agent_id, check_id)
)
CREATE INDEX IF NOT EXISTS idx_posture_findings_agent ON posture_findings (agent_id)
CREATE INDEX IF NOT EXISTS idx_posture_findings_status ON posture_findings (status)
```

Dropped relative to `findings`: `technique_name`/`tactic`/`source_type`/
`attack_data_source`/`security_product_snapshot`/`last_campaign_id`/`resolved_by` —
all BAS-specific concepts (ATT&CK technique metadata, installed-security-product
snapshot, campaign correlation) with no posture-check equivalent. `resolved_by` is
dropped because resolution is automatic-only in this sub-project (always `"system"`,
so not worth a column yet — add it back when Sub-project A gets a manual-override
path, matching `findings.resolved_by`'s actual use).

Each row's occurrence history is **counters, not one row per occurrence** —
`occurrence_count`/`reopened_count`, exactly matching how `findings` already
represents it. This is a settled design precedent, not a new decision: a single
mutable row per `(agent_id, check_id)`, `first_seen` frozen at creation,
`last_observed_at`/`last_seen` advanced on every non-stale observation. (Sub-project
B's `finding_slas` table is where full per-occurrence audit history lives — see
Scope — an append-only table there references `posture_findings.id`, one row per
SLA instance, so a reopened finding gets a *new* SLA row rather than overwriting the
old one. That's a Sub-project B decision to make when it's built, not this one.)

## Lifecycle: reusing `findings.Apply`

`findings.Apply` is already a pure function with no dependency on the BAS domain —
its `Observation` struct is `{Outcome string, RunID string, ObservedAt time.Time}`
and its `State` struct is `{Exists, Status, ExposureState, OccurrenceCount,
ReopenedCount, LastRunID, LastObservedAt, Resolved}`. Both map directly onto
`posture_findings`' columns.

Mapping a posture check's `models.SimulationResult` to an `Observation`:

```go
outcome := "missed"
if r.Result == models.ResultPass {
    outcome = "prevented" // findings.Apply's non-gap branch; "detected_only" is never used here
}
o := findings.Observation{Outcome: outcome, RunID: runID, ObservedAt: r.ExecutedAt}
```

`findings.Apply(s, o)` returns the same `Transition` enum (`Noop`/`Created`/
`Recurred`/`Refined`/`Healed`/`Reopened`/`Stale`) already used for BAS findings; the
new ingest function branches on it identically to `applyFinding` (insert on
`Created`, `UPDATE` otherwise, skip on `Noop`/`Stale`).

## Ingest

New function `upsertPostureFindingsForRun(ctx, runID)` in a new file
`orchestrator/internal/api/posture_finding_handlers.go`, structured as a close
parallel to `upsertFindingsForRun`/`applyFinding` (`finding_handlers.go`):

1. Load the run's `agent_id`, `results`, and `COALESCE(completed_at, started_at)`
   from `scenario_runs` (same query shape as `upsertFindingsForRun`).
2. For each `SimulationResult` with a non-empty `CheckID`, look up its category via
   `h.endpointRiskTaxonomy.CategoryForCheck(checkID)`; skip if category is neither
   `CategorySecurityConfig` nor `CategoryIdentity` (in-scope filter — Application
   Risk's `windows-installed-software`/`linux-installed-software` and any
   Compliance-mapped checks are excluded here, at the same filter point
   `postureCheckInput` already uses for category selection).
3. Aggregate to one `Observation` per `check_id` per run — mirroring
   `upsertFindingsForRun`'s worst-outcome-per-key aggregation, except posture checks
   only have two outcomes (no "worse of missed/detected_only" ranking needed): any
   `ResultFail` in the run makes that check's run-outcome "missed"; only if every
   result for that `check_id` in the run passed does it count as "prevented".
4. Call `applyPostureFinding` (the `posture_findings` analog of `applyFinding`) once
   per `check_id` — same load-current-state → `findings.Apply` → insert/update shape.

**Hook point:** called from `SubmitScenarioResult` (`handlers.go`), immediately after
the existing `h.upsertFindingsForRun(r.Context(), raw.RunID)` call at line 2362 —
same trigger, same idempotency guarantees (a partial/retried submission is safe for
the same reason the comment at `handlers.go:2351-2361` already documents for the BAS
path: the agent only reports steps that ran to completion with a determinate
verdict). **Not** hooked into the detection-ingest path (`detection_handlers.go:134`)
— that hook exists to let EDR/SIEM detection data refine a BAS finding's
`exposure_state` after the fact (missed → detected_only); posture checks have no
such async detection signal, so there's nothing for that hook to feed here.

## API

Two new read-only endpoints, reusing the same permission as the existing endpoint
risk/remediation views (`CanExecuteRemediation` — Analyst+Admin, matching every
other read endpoint in this initiative; no new permission):

- `GET /api/agents/{agentId}/posture-findings` — list this agent's posture findings
  (default: open only; `?status=all` includes remediated).
- `GET /api/posture-findings/{id}` — single finding by ID.

Response shape mirrors `scanFindings`' existing map-based JSON (not a new Go type),
same field-naming convention: `id`, `agentId`, `checkId`, `category`, `title`,
`severity`, `status`, `occurrenceCount`, `reopenedCount`, `firstSeen`, `lastSeen`,
`lastObservedAt`, `lastRunId`, and (when set) `resolvedAt`/`resolvedReason`.

No write/status-override endpoint ships in this sub-project (see Scope).

## Testing

Follows this initiative's established TDD pattern (real Postgres via
testcontainers, not mocks):
- `findings.Apply` itself needs no new tests — it's exercised unchanged.
- New tests for `upsertPostureFindingsForRun`/`applyPostureFinding`, mirroring
  `finding_lifecycle_test.go`'s structure: first-fail creates a row (`open`,
  `occurrence_count=1`), a second failing run recurs (`occurrence_count=2`, same
  row), a passing run heals (`status=remediated`, `resolved_at` set,
  `resolved_reason="re-validated pass"`), a subsequent failing run reopens
  (`status=open`, `resolved_at` cleared, `reopened_count=1`), an out-of-order older
  run is a no-op (`Stale`), and a check outside Security Config/Identity (e.g.
  `windows-installed-software`) never creates a row.
- Handler tests for the two new read endpoints (empty list, populated list,
  `?status=all` filter, 404 on unknown ID), mirroring `finding_handlers_test.go`'s
  shape.
- `TestRBACMatrix_NoDrift` gains the two new routes.

## Migration

One additive `CREATE TABLE IF NOT EXISTS posture_findings (...)` plus its two
indexes in `orchestrator/internal/db/postgres.go`'s migration list, following the
same pattern as every other table added this initiative (e.g. `job_schedules`,
`agent_maintenance_freezes`, `initiatives`). No backfill — the table starts empty
and populates forward from the next scenario run onward; historical `first_seen`
for checks that were already failing before this ships is simply "whenever the
first post-deploy run happens to observe it," which is an accepted, unavoidable
cold-start gap (same as every other table in this initiative that derives state
from `scenario_runs` going forward, e.g. `findings` itself when it first shipped).
