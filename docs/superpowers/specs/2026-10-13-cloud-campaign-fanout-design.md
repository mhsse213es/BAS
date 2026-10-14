# Cloud Campaign Fan-Out Design

Sub-project #4 of the Cloud BAS wiring initiative. Sub-projects #1-3 are done
and merged: the `cloud_runs` data model and lifecycle, the `CloudPlan`
execution harness (`db.ExecuteCloudPlanRun`, one account per call), and the
HTTP API surface (`POST`/`GET /api/cloud-runs`, `GET /api/cloud-runs/{id}`) —
all single-account, single-run. This sub-project lets one request fan `
ExecuteCloudPlanRun` out across multiple accounts at once, tracked as a group,
the way this codebase's existing on-prem `Campaign` concept
(`internal/campaign`, `internal/api/campaign_handlers.go`) already fans a
scenario out across multiple agents today.

Sub-project #5 (hybrid AD-to-cloud, cloud-ransomware scenario wiring) is out
of scope and comes after this.

## Relationship to the pre-existing `cloudgraph` scaffolding

`internal/cloudgraph/campaign_scope.go` and `multiaccount.go`
(`CloudCampaignScope`, `CloudChildRun`, `CloudAggregate`, `RunMultiAccount`)
already exist, committed 2026-10-12 as part of the original 16-week Cloud BAS
architecture (`docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`,
Phase 1 foundation contracts, anticipating Phase 3's "multi-account fan-out"
milestone). They are **not used by this design** and are left untouched.

The reason: `CloudChildRun.Outcomes` is typed `[]*CloudControlOutcome` — a
rich execution-and-telemetry model (`ExecutionOutcome`, `ControlVerdictReason`,
`EventCorrelation`, `TelemetryDelay`) that assumes real per-account discovery,
real execution, and real CloudTrail-style correlation evidence (the
architecture spec's Phase 2). What sub-projects #1-3 actually built this week
is simpler: `ExecuteCloudPlanRun` evaluates a caller-supplied fixture graph
and returns a `*cloudrun.CloudRun` with only a `Status`
(`completed`/`failed`/`partial`) — there is no `CloudControlOutcome` data
anywhere to populate `CloudChildRun.Outcomes` with, and `CloudAggregate`'s
`Prevented`/`Detected`/`Missed`/`Errored` counts would all read zero
permanently. Reusing these types now would conflate "did the graph evaluation
complete" with "did a security control prevent or detect an attack" — two
different, not-yet-equivalent things. This design builds a smaller, honest
set of campaign-specific types against what `ExecuteCloudPlanRun` actually
produces today, and leaves `CloudCampaignScope`/`CloudChildRun`/
`CloudAggregate`/`RunMultiAccount` reserved for whichever later phase
supplies real `CloudControlOutcome` evidence.

## Decisions

1. **Request shape: N full sub-requests, not one shared graph + N accounts.**
   Each cloud account's IAM graph is realistically different content, not
   just a different `AccountScope` tag on identical edges. The campaign
   request body is `{name, runs: [...]}`, where each element of `runs` is a
   complete `{scenarioId, account, edges, held, target, maxHops}` — the exact
   shape `POST /api/cloud-runs` already accepts for one account, repeated N
   times. Wire format stays camelCase, matching `TriggerCloudPlanRun`'s
   existing convention.

2. **Execution is synchronous, not async/poll.** `CloudPlan` has no I/O today
   (sub-project #3's own Decision 1) — fanning out across even 25 accounts is
   a fast in-memory loop. One HTTP request blocks until every account's
   evaluation finishes and returns the complete campaign result in one
   response. No background worker, no stop endpoint, no polling GET — those
   solve a problem (long-running remote execution) that doesn't exist yet for
   cloud runs. Revisit if/when real discovery or provider API calls make a
   single account's evaluation slow.

3. **Dispatch loop is sequential, not concurrent.** The on-prem
   `CreateCampaign` dispatches sequentially despite making real network calls
   per agent; `CloudPlan` is pure in-memory CPU work with nothing to overlap.
   `cloudgraph.RunMultiAccount`'s bounded-concurrency helper is not used, for
   the same reason as item above — reserved for a later phase, not needed
   here.

4. **No "skipped" state.** On-prem campaigns can skip a target discovered
   offline only at dispatch time (group/all resolution happens server-side,
   and agent availability is unknown until that moment). This design has no
   server-side target resolution — the caller lists every account explicitly
   — so there is no reachable scenario that produces a pre-dispatch skip. A
   malformed sub-request rejects the *entire* campaign request (400, nothing
   persisted); a sub-request that evaluates and fails becomes a real
   `cloud_runs` row with `status = failed`. Add a skip concept later only if
   a real exclusion mechanism (e.g., server-side account-group resolution)
   is introduced.

5. **Rollup contract: `{total, completed, partial, failed}`.** No `running`
   (structurally always zero in a synchronous design — the same
   always-empty-field problem avoided by not reusing `CloudAggregate`). No
   `skipped` (see Decision 4). Invariant: `total = completed + partial +
   failed`, for every submitted sub-request that was accepted by validation.

6. **Permission: reuse `auth.CanRunScenario`.** On-prem's dedicated
   `auth.CanCreateCampaign` permission is never actually granted separately
   from `CanRunScenario` in any role definition today (`RoleAdmin` and
   `RoleAnalyst` both grant both, together, in every block) — inventing a
   second named permission here would draw a distinction that doesn't exist
   anywhere else in this feature. Matches `TriggerCloudPlanRun`'s own gate
   exactly.

7. **Request cap: 25 accounts**, a package-level constant
   (`maxCloudCampaignAccounts = 25`), enforced before any persistence.

8. **Validation happens entirely before any persistence**, reusing
   `TriggerCloudPlanRun`'s existing field-level checks (extracted into a
   shared helper — see "Validation contract" below) rather than a second,
   subtly-different implementation in the campaign handler.

## Schema

New table, mirroring `campaigns`/`scenario_runs.campaign_id`'s shape:

```sql
CREATE TABLE IF NOT EXISTS cloud_campaigns (
    id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name       text        NOT NULL,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT NOW()
)
ALTER TABLE cloud_runs ADD COLUMN IF NOT EXISTS campaign_id text
CREATE INDEX IF NOT EXISTS idx_cloud_runs_campaign ON cloud_runs (campaign_id)
```

Deliberately minimal — unlike on-prem `campaigns`, there is no `scenario_id`,
`mode`, `subset`, `targets`, `skips`, `tags`, or `target_type` column at the
campaign level, because every one of those concepts now lives per-sub-request
(each account can run a different scenario, graph, and target), not shared
across the whole campaign the way one on-prem campaign shares one scenario
across all its agents.

### Type changes

`internal/cloudrun/types.go` — `CloudRun` gains one field:

```go
CampaignID string `json:"campaignId,omitempty"`
```

`internal/db/cloudrun_executor.go` — `CloudPlanRunRequest` gains one field,
server-set only, same pattern as the existing `InitiatedBy`:

```go
CampaignID string `json:"-"`
```

`ExecuteCloudPlanRun` passes `req.CampaignID` straight into the `cloudrun.CloudRun{}` it constructs before `InsertCloudRun` — no other change to its logic, branches, or error contract. `InsertCloudRun`, `scanCloudRun` (shared by `GetCloudRun`/`ListCloudRuns`), and the `INSERT`/`SELECT` column lists in `internal/db/cloudrun_store.go` all gain `campaign_id`. A new `ListCloudRunsByCampaign(ctx, pool, campaignID string) ([]*cloudrun.CloudRun, error)` is added alongside the existing `ListCloudRuns`, for the compute-on-read rollup described below.

## Validation contract

Extract `TriggerCloudPlanRun`'s three existing checks into a shared,
unexported helper in `internal/api/cloudrun_handlers.go`:

```go
func validateCloudPlanRunRequest(req db.CloudPlanRunRequest) error {
    if req.ScenarioID == "" {
        return errors.New("scenarioId required")
    }
    if req.Target == "" {
        return errors.New("target required")
    }
    switch req.Account.Provider {
    case "aws", "azure", "gcp":
        return nil
    default:
        return errors.New("invalid provider — use aws | azure | gcp")
    }
}
```

`TriggerCloudPlanRun` is refactored to call this helper (behavior-preserving —
same three checks, same error strings, same order) instead of inlining the
checks. `CreateCloudCampaign` validates, in order, before touching the
database:

1. `name` non-empty, `runs` non-empty.
2. `len(runs) <= 25` (`maxCloudCampaignAccounts`).
3. Every element of `runs` passes `validateCloudPlanRunRequest`. The first
   failing index is named in the 400 response (`"runs[3]: target required"`)
   so the caller can find which sub-request is wrong without resending one at
   a time.

Any failure here returns `400` with nothing persisted — no campaign row, no
`cloud_runs` rows, no audit entry (matching `TriggerCloudPlanRun`'s own
precedent: a pure pre-flight validation failure returns before the handler's
one audit call, same as it does today).

**Duplicate accounts are allowed.** A campaign may legitimately want to run
the same account against two different scenarios/graphs; each `runs[i]` is
evaluated independently regardless of whether its `account` matches another
element's. No de-duplication, no rejection.

**Per-sub-request size bound.** To prevent a campaign with few accounts from
carrying an unbounded payload (the aggregate risk the per-account endpoint
doesn't currently need to worry about), each sub-request's `edges` list is
capped at 500 entries (`maxEdgesPerAccount`), checked in the same up-front
validation pass, same 400-with-index-named behavior. This is additive to
`TriggerCloudPlanRun`'s own validation only when called from the campaign
path — the single-run endpoint is unchanged (matching its own documented,
accepted limitation of no body-size cap, per sub-project #3's final review).

## Execution flow

`CreateCloudCampaign`, `POST /api/cloud-campaigns`, gated by
`auth.RequirePermission(auth.CanRunScenario)`:

1. Decode `{name, runs}`. Run the validation contract above. Any failure:
   `400`, nothing persisted, no audit.
2. Insert the `cloud_campaigns` row. Failure: `500`, audit as `"error"` with
   an empty resource (nothing has an ID yet — mirrors `TriggerCloudPlanRun`'s
   own handling of `ExecuteCloudPlanRun`'s `InsertCloudRun`-failure branch,
   the one case with no row and no ID to report).
3. Loop sequentially over `runs`. For each sub-request, overwrite its
   `InitiatedBy` from the authenticated caller (never client-supplied, same
   as the single-run endpoint) and set `CampaignID` to the new campaign's ID,
   then call the existing, unmodified `db.ExecuteCloudPlanRun`. Capture
   `(run, err)` for every call — this loop cannot abort partway: one
   account's `ExecuteCloudPlanRun` call returning an error never stops the
   loop from proceeding to the next account (isolation is free here, because
   `ExecuteCloudPlanRun` itself already never panics and already returns a
   real, persisted row whenever one exists, per sub-project #3's Decision
   10).
4. Build each sub-request's result and the rollup **directly from the loop's
   own captured `(run, err)` pairs** — never a re-query. Execution is
   synchronous and terminal: by the time step 4 runs, nothing about any
   child run changes again, so the loop's own captured state is already
   final and authoritative.
5. Audit once, outcome `"ok"`, resource = the campaign ID, with the rollup
   counts in the audit detail. A campaign-level audit of `"ok"` means *the
   request was accepted and every submitted sub-request was processed* — it
   does **not** mean every sub-request succeeded. Some, or all, child
   evaluations may have individually failed; that is reflected in the
   rollup's own `failed` count and in each per-account result, never in the
   audit outcome.
6. Respond `201` with:

```json
{
  "campaignId": "...",
  "name": "...",
  "summary": {"total": 3, "completed": 2, "partial": 0, "failed": 1},
  "results": [
    {"account": {"provider": "aws", "accountId": "111"}, "runId": "...", "status": "completed"},
    {"account": {"provider": "aws", "accountId": "222"}, "runId": "...", "status": "failed", "error": "cloud run ...: ..."},
    {"account": {"provider": "azure", "accountId": "333"}, "status": "failed", "error": "cloud_runs: insert ...: ..."}
  ]
}
```

The third example result shows the one case where `runId` is absent: the
sub-request's own `InsertCloudRun` failed entirely (no row was ever
persisted for it, same underlying case sub-project #3's `currentRunOrNil`
documents). It is still counted in `summary.failed` and still carries the
account and error text — nothing about a submitted evaluation is dropped
silently, only its `runId` is genuinely absent because nothing exists to
reference.

### Per-account result status: never invented, always `run`'s own truth

A per-account result's `status` field is **`run.Status` verbatim whenever
`run != nil`**, independent of whether `err` is also non-nil. This matters
for one specific branch: if `UpdateCloudRunStatus`'s own write fails (the
last of `ExecuteCloudPlanRun`'s four error branches), the row's true,
re-fetched status can be `running` — the attempted transition to a terminal
status never actually applied. A naive "err != nil → status: failed" mapping
would misreport this case as a confirmed failure when the honest answer is
"we don't know; the update itself didn't go through." The campaign handler
never overwrites a real `run.Status` with its own guess.

For the **rollup's** three buckets (`completed`/`partial`/`failed`), every
result is folded in as follows:

- `run != nil`: use `run.Status` directly when it is `completed`, `partial`,
  or `failed`.
- `run != nil` but `run.Status` is `running` or `pending` (the
  `UpdateCloudRunStatus`-failure edge case, or any other case where a
  terminal status was never confirmed): counted as `failed` for rollup
  purposes only — the evaluation's outcome could not be confirmed, which is
  not a success. The per-account result's own `status` field still shows the
  literal `"running"` truth; only the aggregate bucket folds it in as
  `failed`.
- `run == nil` (the `InsertCloudRun`-failure case): counted as `failed`.

This keeps the `total = completed + partial + failed` invariant exact for
every *accepted* sub-request (everything that passed the up-front validation
in step 1), while never fabricating a per-account `status` string that isn't
literally what the row (or the error) says.

## `GET /api/cloud-campaigns` and `GET /api/cloud-campaigns/{id}`

Same baseline-auth-only gate as `ListCloudRuns`/`GetCloudRun` (no permission
wrapper beyond authentication — matches that existing precedent). Both
compute their rollup fresh via `ListCloudRunsByCampaign`, querying
`cloud_runs WHERE campaign_id = $1` — compute-on-read, matching the on-prem
pattern, never a second stored copy of the rollup.

`GET /api/cloud-campaigns` lists campaigns (not their child runs), newest
`created_at` first, with the exact same `limit` clamping convention as
`ListCloudRuns` (default 20, max 100, malformed/out-of-range silently falls
back — never a 400). Each listed campaign includes its own rollup, computed
the same way `GET /api/cloud-campaigns/{id}` does, once per campaign in the
page (this is the same N+1-shaped compute-on-read the on-prem
`ListCampaigns`/`campaign.ListWithRollups` already does today — not a new
cost pattern this design introduces).

**This re-query can only ever see rows that were actually persisted.** If a
sub-request's own `InsertCloudRun` failed entirely at creation time (no row,
ever), a later `GET` has no way to reconstruct that it was ever submitted —
it simply isn't in `cloud_runs`. Consequently:

- The `POST` response's `summary.total` and `results` reflect **every
  submitted sub-request that passed validation** (including the
  zero-or-more that failed to even persist a row).
- A later `GET`'s `summary.total` and `results` reflect **only the
  `cloud_runs` rows that exist** for that campaign ID.

These two numbers can legitimately differ by the count of total-insert
failures from the original request. This is a known, documented consequence
of `ExecuteCloudPlanRun`'s existing contract (no synthetic row is ever
created just to make a later read match an earlier one), not a bug to design
around with additional persistence. A `GET` response's `summary` is
documented as "persisted child runs," not "everything once submitted" — the
two endpoints are never claimed to agree on `total`.

## Out of scope

- Fleet-wide report/PDF/CSV exports (the on-prem campaign's
  `GetCampaignReport`/`GetCampaignPDF`/`GetCampaignCSV` equivalents) — no
  cloud-run report format exists yet; a later sub-project's job.
  Account-group / "all accounts" server-side resolution (on-prem's
  `targetType: group | all`) — there is no cloud equivalent of an agent
  fleet to resolve against yet.
- A "stop campaign" operation — nothing to stop in a synchronous design (see
  Decision 2).
- Any use of `cloudgraph.CloudCampaignScope`/`CloudChildRun`/`CloudAggregate`/
  `RunMultiAccount` (see "Relationship to the pre-existing `cloudgraph`
  scaffolding" above) — untouched, reserved for a later phase.

## Testing

- Schema/type changes: `go build ./...` clean (additive only).
- `db` layer: `ExecuteCloudPlanRun` correctly threads `CampaignID` through to
  the persisted row; `ListCloudRunsByCampaign` returns only rows for the
  given campaign ID, newest first (or whatever ordering `ListCloudRuns`
  already uses — match it).
- `api` layer:
  - Successful campaign with 3 accounts, all evaluations completing →
    `summary = {total:3, completed:3, partial:0, failed:0}`.
  - One malformed sub-request among several valid ones → whole request
    `400`, zero `cloud_campaigns` rows, zero `cloud_runs` rows (nothing
    partially persisted).
  - `len(runs) == 26` → `400`, nothing persisted.
  - A sub-request whose provider/edges mismatch (the existing
    `validateEdgesMatchProvider` rejection) → that result's `status =
    "failed"`, `runId` present, `error` present, rollup `failed` includes it,
    **other accounts in the same campaign still complete normally** (the
    core isolation guarantee).
  - `InitiatedBy` and `CampaignID` are always server-controlled on every
    sub-request, even if the client sends different values in the body for
    some or all of them (mirrors sub-project #3's own
    `TestTriggerCloudPlanRun_InitiatedByIsAlwaysServerControlled`).
  - Audit fires once per campaign creation, outcome `"ok"`, even when some
    (not all) sub-requests individually failed — the rollup counts are in
    the audit detail, proving the "ok" outcome never means "every evaluation
    succeeded."
  - `GET /api/cloud-campaigns/{id}` round-trips a created campaign's rollup
    from `cloud_runs`, independent of the original in-memory loop result.
  - `rbac_matrix_test.go` rows for all three new routes, matching Decisions
    6 and the baseline-only GET precedent.
