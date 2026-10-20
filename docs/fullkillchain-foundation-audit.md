# Full Kill Chain: Foundation Audit and Design

Status: draft for review, 2026-10-20. Source requirements: `fullkillchain.txt`.
This step writes no runtime code and no scenarios. Every baseline claim below was
checked against the repository on this date. File references are to the state of
`main` at `fa86237c`.

## 1. Verified baseline

Legend: **Implemented** = working code with tests. **Partial** = real code that covers
part of the requirement. **Missing** = not present.

### 1.1 Campaign and stage structure

| Capability | Status | Where | Notes |
|---|---|---|---|
| Campaign rollup (status, progress, result mix over child runs) | Implemented | `internal/campaign` | Aggregates runs. No stage graph. **Not reused as a stage model.** |
| Ordered stages with prerequisite blocking (EmailGW only) | Partial | `internal/emailgwcampaign`, `internal/api/emailgwcampaign_executor.go`, table `email_gw_campaign_stages` | Stages have an `ordinal` and a `blocked_by_prerequisite` status. The shape is a **linear sequence**, not a graph. No branching. |
| AD capability-state chaining | Implemented, AD only | `internal/adchain`, `internal/adcompose` | Resolves which AD capabilities are satisfied before a dependent step. **Not reused.** |
| Cross-domain campaign engine | Missing | none | No campaign ID spanning email, endpoint, identity, network, cloud and data. |

### 1.2 Verdicts and outcomes

| Capability | Status | Where | Notes |
|---|---|---|---|
| Prevention / detection / response split (phishing) | Implemented | `internal/phishval` `Outcome`: `Delivery`, `Enforcement`, `Detection`, `UserInteraction`, `Response` | Separate dimensions with their own results. Domain-local. |
| Enforcement / classification / telemetry / response split (DLP) | Implemented | `internal/dlpreport/record.go` | Four outcome enums. `Telemetry` values include `Absent`, `Present`, `Delayed`, `Incomplete`, `Unverifiable`. Domain-local. |
| Per-control outcome (access controls) | Implemented | `internal/controlval` | `allowed`, `blocked`, `mfa_challenged`, `terminated`, `quarantined`, `unknown`. Plus `PASS`/`FAIL`/`ERROR`/`SKIPPED`. |
| PAN-OS exposure verdict | Implemented | `internal/panosexposure` | `vulnerable`, `mitigated`, `not_affected`, `unknown`, `not_applicable`, with reason codes. |
| **Unified eight-verdict vocabulary** | **Missing** | none | `BLOCKED`, `DETECTED`, `ALLOWED`, `DETECTED_NOT_CONTAINED`, `NOT_DETECTED`, `NOT_TESTED`, `INCONCLUSIVE`, `ERROR` do not exist as one type. `NOT_TESTED` appears in one Go file. `DETECTED_NOT_CONTAINED`, `NOT_DETECTED` and `INCONCLUSIVE` appear in none. |

**Finding that differs from the document's baseline:** the document implies no
prevention/detection/response separation exists. It does, in three domains, each
with its own enum. What is missing is a shared contract that all of them map to.

### 1.3 Execution, evidence and audit

| Capability | Status | Where |
|---|---|---|
| Scenario engine, signed YAML scenarios | Implemented | `internal/scenario`; `.sig` files; re-sign after every edit |
| Execution authorization | Implemented | `auth.CanRunScenario` (`scenarios:run`), `internal/auth/permissions.go` |
| Unified execution attempts | Implemented | table `execution_attempts` (Phase 0B) |
| Run events and audit | Implemented | tables `run_events`, `audit_logs` |
| Per-domain run tables | Implemented | `scenario_runs`, `email_gw_runs`, `phishing_runs`, `cloud_runs`, `variant_runs` |
| Evidence storage | Implemented | `exercise_evidence`, `technique_evidence`, `verification_evidence` (+ blob), `relationship_evidence` |
| Ground truth as a general concept | Partial | Present in the DLP classifier (`internal/dlpclassify`) and some handlers. No per-stage ground-truth record. |
| Campaign-scoped evidence correlation | Missing | No table or key links evidence across runs of one campaign. |

### 1.4 Coverage

| Capability | Status | Where | Notes |
|---|---|---|---|
| Four-level maturity ladder for phishing scenarios | Implemented | `internal/phishcatalog/coverage.go`: `catalog-only` < `fixture-tested` < `adapter-tested` < `live-validated`, with `RequireNoCoverageRegression` | **No lab-validated level.** The document requires one. |
| Scenario library capability status | Implemented | `internal/api/scenario_library_handlers.go` | Reports what this installation can run now, with a reason. Not a maturity ladder. |
| Coverage by domain, platform, control and campaign | Missing | none | Only per-catalog coverage exists. |

### 1.5 Tenancy and scoping

- The deployment is single-tenant per installation.
- `auth.Claims` carries a `TenantID` (`internal/auth/jwt.go`).
- The `tenant_id` column appears in `cloud_runs`, the content tables, the exercise schema and some others. The phishing run store has **no** column; a comment in `internal/db/phishingrun_store.go:21` records that decision.
- **Finding:** the schema is not consistent about `tenant_id`. The new design must follow the sibling-run precedent (no tenant column), and this needs a decision (section 8).

## 2. Campaign model

### 2.1 Identity

- `campaign_id`: stable, text, generated at creation, never reused.
- `stage_id`: stable within a campaign. Format `<campaign_id>/<stage_key>`, where `stage_key` is an authored, unique, lowercase identifier from the campaign definition.
- `execution_id`: one per attempt at a stage. This is `execution_attempts.id` (existing) and is not redefined.

### 2.2 Definition (authored, versioned, signed)

A campaign definition is a directed acyclic graph:

- **Nodes:** stages. Each names a scenario ID and a variant, or a dependency on an external outcome.
- **Edges:** `requires` (hard prerequisite) and `on` (branch condition on an upstream verdict).
- **Rules:**
  - A stage with no path from a root stage is invalid. Reject at load time.
  - Cycles are invalid.
  - A branch condition may only reference verdicts of upstream stages.
  - Each campaign definition carries a version and is signed like a scenario.

This is a **generalisation** of the existing linear `email_gw_campaign_stages` model, not a replacement. The EmailGW campaign keeps its own table and behaviour.

### 2.3 Execution state

Per stage: `pending`, `dispatched`, `completed`, `blocked_by_prerequisite`, `not_reached`, `failed`, `cancelled`, `interrupted`.

- `not_reached`: the stage's required prerequisite produced a verdict that closes its path (for example, initial access blocked). Recorded as `NOT_TESTED` in the verdict engine. It is **never** recorded as a pass.
- `blocked_by_prerequisite`: the existing EmailGW state, reused by name.
- `interrupted`: the process stopped while the stage was `dispatched`. Partial evidence is kept.

### 2.4 Causal links

Every evidence record for a stage carries `campaign_id`, `stage_id`, `execution_id`, and an optional `caused_by` reference to an upstream evidence record. Causal links form a DAG that matches the campaign graph. An evidence record cannot cite a stage that is not upstream of it.

### 2.5 Interrupted runs

- On restart, the orchestrator reconciles every campaign in `dispatched` or `interrupted` status.
- A stage with partial evidence is marked `interrupted` and keeps its evidence. It is never silently completed.
- The campaign result is marked `partial` until every reachable stage has a verdict.
- The existing `StatusPartial` (`phishingrun`) and run reconciliation (`project_run_reconciliation`) are the reference. Do not invent a new reconciliation mechanism.

### 2.6 Branching and alternate paths

- Each stage declares its alternate paths in the definition. A campaign that blocks at initial access follows the alternate branch. The downstream stages on the blocked path are `not_reached`, not failed.
- A stage whose required telemetry source is not operational is `INCONCLUSIVE`, not `NOT_DETECTED`.

## 3. Evidence contract

### 3.1 Required fields per stage outcome

| Field | Purpose |
|---|---|
| `ground_truth` | Authoritative record of what actually happened, from a source independent of the security product (for example, the executing host's own process record, or the synthetic file's own hash). |
| `ground_truth.source` | Which independent source produced it. |
| `prevention` | Outcome of the control that was supposed to stop the action. Values: `blocked`, `allowed`, `not_applicable`, `unknown`. Plus `control_id` and `stage_reached`. |
| `detection` | Whether the expected telemetry produced a detection. Values: `detected`, `not_detected`, `inconclusive`, `not_applicable`. Plus `alert_id`, `telemetry_source`, `telemetry_status`. |
| `response` | Whether the detection became an incident and whether containment was verified. Values: `incident_created`, `contained_verified`, `not_contained`, `not_applicable`, `inconclusive`. |
| `provenance` | Source system, collector version, query or extraction reference, and the time it was read. |
| `timestamps` | Action time (from ground truth), event time (from the product), ingestion time, and observation-window start and end. |
| `correlation_ids` | `campaign_id`, `stage_id`, `execution_id`, `caused_by`, and vendor event identifiers. |
| `missing_evidence` | Explicit list of required items that were absent. |

### 3.2 Missing-evidence rules

- A missing field is recorded in `missing_evidence`. It is never read as `false`, `none` or `not_detected`.
- Absence of a telemetry source is `inconclusive` for detection. It is not a detection failure.
- A success response from an API is not evidence of a prevention outcome. A console alert is not evidence of containment.
- Each evidence type states which fields are required and which are optional. A scenario that cannot supply a required field is downgraded, not passed.

### 3.3 Mapping existing outcomes

The existing per-domain outcomes map into this contract. The mapping is a pure function, one per domain. Each domain's own enum stays as its evidence value; the mapping decides the contract value.

| Existing | Maps to |
|---|---|
| `phishval.EnforcementOutcome` `blocked` | `prevention = blocked` |
| `phishval.Detection` | `detection` |
| `dlpreport` `TelemetryAbsent` | `detection = inconclusive` with `missing_evidence` entry. Not `not_detected`. |
| `controlval` `allowed` | `prevention = allowed` |

Each mapping needs fixture tests and a written list of ambiguous source values. An ambiguous source value maps to `unknown`.

## 4. Verdict engine

### 4.1 The eight verdicts

Each stage gets a **stage verdict**, and each dimension keeps its own value. The stage verdict is derived; it never replaces the dimension values.

| Verdict | Meaning | Required condition |
|---|---|---|
| `BLOCKED` | The tested action was demonstrably prevented. | `prevention = blocked` with verified ground truth showing the action was attempted and stopped. |
| `DETECTED` | The expected behaviour was detected with sufficient evidence. | `detection = detected` and telemetry status is complete. Not necessarily blocked. |
| `ALLOWED` | The action occurred although a verified policy should have prevented it. | `prevention = allowed` and ground truth shows the action occurred, plus a verified policy stating it should be prevented. |
| `DETECTED_NOT_CONTAINED` | Detection occurred, containment was required and not verified. | `detection = detected` and `response = not_contained` or containment not verified. |
| `NOT_DETECTED` | The test ran, the observation window completed, required telemetry was confirmed operational, and the expected detection was absent. | `detection = not_detected`, observation window complete, telemetry health confirmed. |
| `NOT_TESTED` | Prerequisites were missing, or the stage was not reached. | Stage state `not_reached` or prerequisite evidence missing. |
| `INCONCLUSIVE` | Evidence was insufficient, contradictory or unreliable. | Any required field in `missing_evidence`, or contradictory values, or telemetry health unknown. |
| `ERROR` | Execution or verification failed for a technical reason. | Execution attempt failed, or the verifier itself failed. |

### 4.2 Deterministic evaluation rules

Evaluation is a pure function of the stage's evidence and definition. It has no database or network access and no clock except the one passed in.

Precedence, highest first:

1. `ERROR`: any execution or verifier failure. Nothing else is evaluated.
2. `NOT_TESTED`: stage not reached, or prerequisite evidence missing before execution.
3. `INCONCLUSIVE`: any required field missing, contradictory, or telemetry health unknown.
4. `ALLOWED`: a verified policy violation was observed. This overrides detection, because an allowed action is a control failure regardless of alerts.
5. `BLOCKED`: prevention verified. Detection and response are still reported separately.
6. `DETECTED_NOT_CONTAINED`: detected, but containment required and not verified.
7. `DETECTED`: detected with complete evidence.
8. `NOT_DETECTED`: complete window, telemetry confirmed healthy, no detection.

### 4.3 Outcomes that must remain independent

These are never collapsed into one verdict, even when one implies another:

- **Prevention and detection.** A stage can be `BLOCKED` and also `DETECTED`. The report shows both.
- **Detection and response.** `DETECTED` with `not_contained` must not be shown as a pass. This is why `DETECTED_NOT_CONTAINED` exists.
- **Stage and campaign.** A campaign with one `ALLOWED` stage is not a campaign pass, even if every other stage is `BLOCKED`.
- **Verdict and confidence.** Confidence and evidence completeness are reported beside the verdict, never folded into it.

### 4.4 Campaign-level rollup

- Campaign verdict is derived from stage verdicts, not from a count.
- Any `ALLOWED` or `ERROR` stage makes the campaign's failure visible regardless of the others.
- `NOT_TESTED` stages are excluded from every denominator. They are reported as a count, never as passes.

## 5. Coverage maturity

Five levels, each a separate dimension:

| Level | Meaning | Evidence required |
|---|---|---|
| Cataloged | Scenario and objective defined. | Signed scenario definition. |
| Fixture-tested | Evaluation logic tested against deterministic fixtures. | Fixture tests pass. |
| Adapter-tested | Integration and evidence handling tested against an adapter. | Adapter tests with recorded responses. |
| Lab-validated | Executed against a representative controlled environment. | Lab run record with ground truth. |
| Live-validated | Executed against the supported product under authorisation. | Authorised live run record. |

Plus `Unsupported`, which is not a maturity level and is shown separately.

**Required change:** the existing phishing ladder has no `lab-validated` tier. Options are in section 8.

Reporting rules:

- Coverage is reported as a table keyed by **domain, platform, control and campaign**. Each row shows counts per level.
- No single percentage is produced.
- A metric's denominator is stated with it, along with its eligibility rule and observation window.
- An untested or unsupported stage never raises a coverage figure.
- `RequireNoCoverageRegression` (`phishcatalog`) is the existing regression check and is reused for this.

## 6. Architecture and reuse

### 6.1 Reuse, unchanged

- `scenario` engine and signed scenario definitions.
- `auth.CanRunScenario` (`scenarios:run`) for every campaign stage.
- `execution_attempts`, `run_events`, `audit_logs`, existing evidence tables.
- `phishcatalog.RequireNoCoverageRegression` and the phishing ladder's code.
- Run reconciliation and `StatusPartial`.
- The idempotent `CREATE TABLE IF NOT EXISTS` schema convention in `internal/db`.

### 6.2 New, minimal

- `internal/killchain` (pure): campaign definition types, DAG validation, stage states, evidence contract, verdict engine, coverage model. **No database access, no vendor SDKs.**
- `internal/db/killchain_store.go`: tables `killchain_campaigns`, `killchain_stages`, `killchain_stage_evidence`, `killchain_edges`. New tables only. No existing table is altered.
- `internal/api/killchain_*`: routes under `/api/killchain/...`, each added to the RBAC route matrix.

### 6.3 Not built, deliberately

- No new execution engine. The existing one is called.
- No second evidence store. Evidence rows reference existing evidence records.
- No shared-database multi-tenancy. No tenant column is added (section 8).

## 7. Phased implementation plan

Each phase ends with an exit condition. A phase is not complete until its exit condition is met, and claims are limited to what its tests show.

### Phase 0: this audit

- **Acceptance:** this document, reviewed. Decisions in section 8 answered.
- **Tests:** none (no code).
- **Dependencies:** user review.
- **Exit:** approval of section 8 decisions.

### Phase 1: pure model and verdict engine

- **Scope:** `internal/killchain` types, DAG validation, the eight verdicts, precedence, evidence contract, mapping functions for `phishval`, `dlpreport`, `controlval`.
- **Acceptance:**
  - Every verdict has at least one table test that produces it and at least one that does not.
  - Precedence test for every pair where two rules could both apply.
  - A missing required field never yields `BLOCKED`, `DETECTED` or `NOT_DETECTED`.
  - An `ALLOWED` stage makes the campaign failure visible.
  - Evaluation is deterministic: same input gives same output, and the clock is an argument.
  - DAG validation rejects cycles, orphaned stages and branch references to non-upstream stages.
- **Tests:** unit tests only, no database.
- **Dependencies:** none.
- **Exit:** all tests pass; a written list of ambiguous source values for each mapping.

### Phase 2: persistence and orchestration

- **Scope:** `killchain_*` tables, store, orchestrator that walks the DAG, dispatches stages through the existing execution path, and reconciles interrupted campaigns.
- **Acceptance:**
  - Schema creation is idempotent (run twice, no error).
  - A campaign resumes after a simulated crash mid-stage, keeps partial evidence, and marks the stage `interrupted`.
  - A stage whose prerequisite is blocked is `not_reached`, and no execution attempt is created for it.
  - Every stage execution is linked to `execution_attempts` and to an audit record.
  - Campaign status is `partial` until every reachable stage has a verdict.
- **Tests:** store tests against the test database; orchestration tests with a fake execution adapter.
- **Dependencies:** Phase 1; the RBAC drift test (`TestRBACMatrix_NoDrift`) must pass with the new routes.
- **Exit:** orchestration tests and RBAC tests pass.

### Phase 3: evidence correlation

- **Scope:** evidence records linked by `campaign_id`, `stage_id`, `caused_by`; ground-truth record type; per-domain mapping adapters.
- **Acceptance:**
  - Evidence for a stage cannot reference a non-upstream stage.
  - Mapping adapters are total: every source value maps to a contract value or `unknown`.
  - Missing ground truth yields `INCONCLUSIVE`, never `NOT_DETECTED`.
  - A correlated timeline can be produced for one campaign run from its evidence alone.
- **Tests:** fixture-driven tests for each adapter; a golden timeline test.
- **Dependencies:** Phase 2.
- **Exit:** every mapping has fixture tests and a documented ambiguous-value list.

### Phase 4: coverage reporting

- **Scope:** five-level coverage, reported by domain, platform, control and campaign.
- **Acceptance:**
  - No output contains a single combined percentage.
  - Unsupported and untested stages are shown as counts, not as coverage.
  - Each level is set only by evidence of that level. A `lab-validated` mark requires a lab run record.
- **Tests:** report tests with fixture catalogs at each level.
- **Dependencies:** Phases 1 and 3; decision on the lab tier (section 8).
- **Exit:** report tests pass.

### Phase 5: first vertical slice (identity to endpoint to lateral movement to containment)

- **Scope:** one campaign, from the document's recommended first set, using existing scenarios where they exist and naming any gap.
- **Acceptance:**
  - Fixture-level: the campaign produces a correlated timeline and each stage verdict from fixture evidence.
  - Lab-level: the same campaign runs in a representative lab, with ground truth recorded.
- **Tests:** end-to-end fixture test; lab run record (not automatable here).
- **Dependencies:** Phases 1 to 4; lab environment, which is not available to this repository today.
- **Exit:** fixture exit is achievable now. Lab exit is **blocked** until a lab exists. The campaign must not be labelled lab-validated before then.

### Phases 6 and beyond (not planned in detail)

Ransomware and backup assurance, email compromise to finance workflow, cloud identity to data egress, SOC pipeline validation, and application, supply-chain and OT campaigns. Each needs its own design pass after Phase 5, and each must name its lab and live prerequisites before starting.

## 8. Decisions requiring approval

1. **Reuse or replace the EmailGW campaign stage model?** Recommendation: keep `email_gw_campaign_stages` unchanged; add the generalised model beside it. Cost if wrong: two stage models to maintain.
2. **Verdict vocabulary.** Recommendation: adopt the eight verdicts as the stage verdict, and keep each domain's enum as an evidence value. Cost if wrong: existing reports need a mapping layer.
3. **Lab-validated tier.** The phishing ladder has four levels, and the document requires five. Recommendation: add `lab-validated` as a new level for kill-chain campaigns only, and leave the phishing ladder unchanged until its own review. Cost if wrong: two ladders that disagree.
4. **Tenancy.** Recommendation: no tenant column in new tables, matching the phishing and sibling run tables, since the deployment is single-tenant per installation. Note that `tenant_id` appears in several existing tables and in JWT claims, so the codebase is inconsistent and this decision should be made explicitly. Cost if wrong: a later migration to add it.
5. **Campaign definition format.** Recommendation: signed YAML, like scenarios, with DAG validation at load. Cost if wrong: a second format to learn.
6. **Interrupted-run behaviour.** Recommendation: resume from the last completed stage, and never re-execute a stage whose execution attempt exists. Cost if wrong: duplicate side effects on a re-run.

## 9. Findings that differ from the document's baseline

1. Ordered stage execution with prerequisite blocking already exists for EmailGW. It is linear, not a graph.
2. Prevention, detection and response are already separated in three domains, each with its own enum.
3. The phishing store does not have `tenant_id`, but several other tables do, and the JWT carries it. The schema is inconsistent.
4. The phishing coverage ladder has four levels, not the five the document requires.
5. The eight-verdict vocabulary is not present as one type anywhere.

## 10. Backward-compatibility risks

- Adding a `not_reached` or `interrupted` state to any existing enum would break exhaustive switches. This design adds states only in new types.
- `phishcatalog` coverage labels are compared by string in several places. Changing them breaks regression checks. Not changed here.
- Scenario signatures: any scenario added or edited for a campaign must be re-signed (`go run scripts/signer.go verify-all`). Signature checks currently pass for 126 scenarios.
- Test cleanup (`testutil.truncateAll`) enumerates tables from `pg_tables`, so new tables are cleared automatically. `testdb.go` also refers to `email_gw_campaign_stages` by name in one place; check whether new tables need an explicit entry there.
- The RBAC route matrix must include every new route, or `TestRBACMatrix_NoDrift` fails.

## 11. Migration requirements

- New tables only, created with `CREATE TABLE IF NOT EXISTS` in `internal/db`. No `ALTER` on existing tables.
- No data migration. No existing run is reclassified.
- Rollback: drop the new tables. Nothing else depends on them.

## 12. What this document does not claim

- It does not claim any campaign is implemented or validated.
- It does not claim any scenario in `scenarios/` executes as a campaign stage.
- Lab and live validation are not available to this repository today.
