# TCV SLA Event Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an append-only `tcf_pipeline_events` ledger and an internal-SLA projection that measures threat→validated-coverage velocity, leaving the Phase-2C TCV metric untouched.

**Architecture:** The ledger is an event *spine* that references authoritative source rows (provenance `source_table`/`source_pk`, event-time copied from the source) rather than copying mutable facts. Writers emit idempotent events at existing pipeline trigger points; a reconciler re-derives any missed events from source tables (= backfill on a schedule). Two read projections: Phase-2C (unchanged) and the new SLA projection, both read-only over the ledger/sources.

**Tech Stack:** Go, pgx/pgxpool, Postgres; test via `internal/testutil.MustSharedTestDB()` (testcontainers). Package `internal/tcv` (pure + DB), `internal/db` (schema), `internal/connector` + `internal/contentregistry` + `internal/validationlab` (writer wiring), `internal/api` (endpoint).

**Spec:** `docs/superpowers/specs/2026-10-31-tcf-tcv-sla-event-ledger-design.md`

## Global Constraints

- Build from **current `origin/main`**, in a fresh worktree/branch (NOT `tcf-phase2`). TCV source files are identical to the worktree except `analytics/factory.go`.
- Phase-2C stays byte-for-byte: `threat_clock_starts`, `threat_coverage_firsts`, `internal/tcv/{clocks,coverage,metrics,aggregate}.go`, `contentregistry/tcv.go`, `GET /api/intel/threats/{id}/tcv`. Do not edit them.
- Ledger is append-only: app role (`bas_app`) gets INSERT/SELECT only; `REVOKE UPDATE, DELETE ON tcf_pipeline_events FROM bas_app` (mirror `app_role.go`'s `content_version_events` line). Corrections are new rows.
- Ledger writes are **log-and-continue**, never in the source write's transaction; a ledger failure never rolls back a real pipeline action.
- Idempotent inserts: every writer does `INSERT ... ON CONFLICT (idempotency_key) DO NOTHING`.
- Durations computed from `event_time` (source timestamp) only; never `recorded_time`.
- Coverage counts only `validated_coverage`; `published_executable` alone never counts (emulates-hole fix).
- Validation events only from `content_validations` level=`EXECUTION` joined to `scenario_runs.execution_kind='factory_validation'`.
- Grain = per `(threat, relationship_kind)` leg. Percentiles on the `validated` cohort only; `failed`/`open` as counts/rates.
- `minTechniques` = 2 (`connector/generator.go`). No new external dependencies. gofmt clean; new routes get a `routeMatrix` entry (RBAC-drift trap).

## Review Focus

- **Event written outside the source transaction crashes before the ledger insert** (scheduler emits `threat_observed`/`threat_eligible` on `s.pool`) → gap; the reconciler must heal it. Test in Task 6.
- **A threat with both `emulates` and `generated_for` legs** → the two legs are measured independently and never merged/double-counted. Test in Task 7.
- **`validation_resulted` with outcome `NO_DATA`/`ERROR`** (not just PASS/FAIL) → never counted as coverage, never crashes cohort bucketing. Test in Task 5.
- **A leg open in the queue stage (no `threat_eligible`) vs open in validation** → completeness flag distinguishes them; neither counts as a zero duration. Test in Task 7.
- **Backfilled window where some legs lack `threat_eligible`** → excluded from P50/P95 and flagged, not counted as zero. Test in Task 7.

---

### Task 1: Ledger schema, grants, and boot wiring

**Files:**
- Create: `orchestrator/internal/db/tcf_pipeline_events_schema.go`
- Create: `orchestrator/internal/db/tcf_pipeline_events_schema_test.go`
- Modify: `orchestrator/internal/db/app_role.go` (add one REVOKE line)
- Modify: `orchestrator/cmd/server/main.go` (call `EnsureTCFPipelineEventsSchema` after `EnsureGenerationAttemptsSchema`/`EnsureTCVSchema`, before `EnsureAppRole`)

**Interfaces:**
- Produces: `func EnsureTCFPipelineEventsSchema(ctx context.Context, pool *pgxpool.Pool) error`; table `tcf_pipeline_events` with columns per spec §6.

- [ ] **Step 1: Write the failing test** `TestEnsureTCFPipelineEventsSchema` in the new test file: call `EnsureTCFPipelineEventsSchema` twice (idempotent), then assert (a) an INSERT of one row with a unique `idempotency_key` succeeds, (b) a second INSERT of the same `idempotency_key` with `ON CONFLICT DO NOTHING` affects 0 rows, (c) an `event_type` outside the 12-value CHECK is rejected. Use `sharedDB.Pool` + the `MustSharedTestDB` + `TestMain` pattern from `internal/db` tests (run prerequisite `Ensure…Schema` for `threats`/`content_versions` first).
- [ ] **Step 2: Run** `go test ./internal/db/ -run TestEnsureTCFPipelineEventsSchema` — Expected: FAIL (function undefined).
- [ ] **Step 3: Implement `EnsureTCFPipelineEventsSchema`** with the `CREATE TABLE IF NOT EXISTS tcf_pipeline_events (...)` + three indexes from spec §6. Follow the `var …Tables []string` + loop style of `generation_attempts_schema.go`.
- [ ] **Step 4: Run** the test — Expected: PASS.
- [ ] **Step 5: Write the failing test** `TestAppRole_PipelineEventsAppendOnly` (acceptance 12): as `bas_app`, INSERT and SELECT succeed; UPDATE and DELETE are refused. Mirror the existing `content_version_events` app-role test if present.
- [ ] **Step 6: Run** it — Expected: FAIL.
- [ ] **Step 7: Implement** the grant: add `` `REVOKE UPDATE, DELETE ON tcf_pipeline_events FROM ` + appRole `` to `app_role.go`'s statement list; wire `EnsureTCFPipelineEventsSchema` into `main.go` in dependency order.
- [ ] **Step 8: Run** `go test ./internal/db/ -run 'TestEnsureTCFPipelineEventsSchema|TestAppRole_PipelineEventsAppendOnly'` — Expected: PASS.
- [ ] **Step 9: Commit** (`feat(tcv): tcf_pipeline_events schema + append-only grant`).

---

### Task 2: Ledger core — event model, idempotency key, append-only writer

**Files:**
- Create: `orchestrator/internal/tcv/ledger.go`, `orchestrator/internal/tcv/ledger_test.go`

**Interfaces:**
- Produces:
  - `type EventType string` + 12 consts: `EventThreatObserved`, `EventThreatEligible`, `EventGenerationAttempted`, `EventGenerationFailed`, `EventContentCreated`, `EventValidationDispatched`, `EventValidationResulted`, `EventValidatedCoverage`, `EventPublishedExecutable`, `EventSuperseded`, `EventRetired`, `EventRejected` (values = the snake_case strings in the schema CHECK).
  - `type Event struct { Type EventType; ThreatID, ContentID, ContentVersionID, GenerationAttemptID, ValidationRunID string; EventTime time.Time; SourceTable, SourcePK string; Payload map[string]any }`
  - `func (e Event) idempotencyKey() string` — `string(e.Type) + ":" + firstNonEmpty(e.ContentVersionID, e.ThreatID) + ":" + e.SourcePK`.
  - `func RecordPipelineEvent(ctx context.Context, q Querier, e Event) error` — marshals `Payload` to JSON, `INSERT ... ON CONFLICT (idempotency_key) DO NOTHING`; uses the `Querier` seam so a caller's tx or the pool both work.

- [ ] **Step 1: Write the failing test** `TestEvent_IdempotencyKey` (pure): assert the key for a `validation_resulted` event with `ContentVersionID="cv1"`, `SourcePK="val7"` equals `"validation_resulted:cv1:val7"`, and that an event with only `ThreatID="t1"` falls back to `"threat_observed:t1:<pk>"`.
- [ ] **Step 2: Run** `go test ./internal/tcv/ -run TestEvent_IdempotencyKey` — Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `EventType` consts, `Event`, `idempotencyKey`.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Write the failing test** `TestRecordPipelineEvent_WriteOnceAndPayload` (DB-backed, `sharedDB.Pool`): record an event; assert one row with matching `event_type`, `event_time`, `source_table`, `source_pk`, and `payload->>'outcome'`; record the *same* event again → still exactly one row (idempotent); record a different event (different `source_pk`) → two rows.
- [ ] **Step 6: Run** `go test ./internal/tcv/ -run TestRecordPipelineEvent_WriteOnceAndPayload` — Expected: FAIL.
- [ ] **Step 7: Implement** `RecordPipelineEvent` (JSON-marshal payload; INSERT … ON CONFLICT DO NOTHING; derive key from `idempotencyKey()`).
- [ ] **Step 8: Run** — Expected: PASS.
- [ ] **Step 9: Commit** (`feat(tcv): append-only pipeline-event writer + idempotency`).

---

### Task 3: Observation & eligibility events (connector)

**Files:**
- Modify: `orchestrator/internal/connector/scheduler.go` (the trusted-claim branch that already calls `tcv.RecordThreatClockStart`, `resolvePendingClaims`)
- Modify: `orchestrator/internal/connector/generator.go` (the non-skip branch after the `len(activeTechniques) < minTechniques` check)
- Test: `orchestrator/internal/connector/tcv_events_test.go`

**Interfaces:**
- Consumes: `tcv.RecordPipelineEvent`, `tcv.Event`, event-type consts (Task 2).
- Produces: `threat_observed` events (`source_table='source_observations'`, `event_time=observed_at`, payload `{source}`) and `threat_eligible` events (`source_table='content_generation_attempts'` cycle context, `event_time`=cycle time, payload `{}`), both write-once via the ledger's idempotency.

- [ ] **Step 1: Write the failing test** `TestThreatObserved_WrittenOnceFromTrustedClaim` (DB-backed, connector harness): drive the trusted-claim path for a threat; assert exactly one `threat_observed` with `event_time == observed_at` and `payload->>'source'` set; replaying the sync adds no duplicate.
- [ ] **Step 2: Run** `go test ./internal/connector/ -run TestThreatObserved_WrittenOnceFromTrustedClaim` — Expected: FAIL.
- [ ] **Step 3: Implement** the `threat_observed` emit alongside the existing `RecordThreatClockStart` call (same `trustState==Trusted` guard), log-and-continue on error.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Write the failing tests** `TestThreatEligible_FirstClearOnly` (acceptance 1): a threat crossing `minTechniques` emits one `threat_eligible`; a later cycle still above threshold adds none. `TestThreatEligible_NotWrittenBelowThreshold` (acceptance 2): a threat below `minTechniques` emits no `threat_eligible` (its queue stage stays open).
- [ ] **Step 6: Run** both — Expected: FAIL.
- [ ] **Step 7: Implement** the `threat_eligible` emit in `generator.go` on the branch where a threat clears `minTechniques` (before the first generation attempt for that threat), write-once via idempotency key `threat_eligible:<threatID>:<threatID>` (SourcePK=threatID so the first clear wins).
- [ ] **Step 8: Run** `go test ./internal/connector/ -run 'TestThreatObserved|TestThreatEligible'` — Expected: PASS.
- [ ] **Step 9: Commit** (`feat(tcv): observation + eligibility pipeline events`).

---

### Task 4: Generation events (generator)

**Files:**
- Modify: `orchestrator/internal/connector/generator.go` (inside/after `recordAttempt`, the single chokepoint for all attempt outcomes)
- Test: `orchestrator/internal/connector/tcv_generation_events_test.go`

**Interfaces:**
- Consumes: Task 2 writer; the existing `recordAttempt(... outcome, reasonCode ..., startedAt, versionID ...string)`.
- Produces: `generation_attempted` (every attempt), `generation_failed` (outcome `failed`), `content_created` (outcome `created`/`changed`, carries `content_version_id`); `source_table='content_generation_attempts'`, `source_pk`=the cga row id, `event_time`=`started_at`/`completed_at` per spec §5.

- [ ] **Step 1: Write the failing test** `TestGenerationEvents_AttemptFailThenCreate` (acceptance 3): a failed attempt produces `generation_attempted` + `generation_failed`; a later successful attempt produces `content_created` with the right `content_version_id`; assert `event_time` of `content_created` matches the version's `created_at` (or cga `completed_at` per §5) and the attempt is linked via `generation_attempt_id`.
- [ ] **Step 2: Run** `go test ./internal/connector/ -run TestGenerationEvents_AttemptFailThenCreate` — Expected: FAIL.
- [ ] **Step 3: Implement** emits from `recordAttempt` keyed on `outcome`: always `generation_attempted`; `failed`→`generation_failed`; `created`/`changed`→`content_created` (only this one sets `ContentVersionID`). Reuse the cga row id as `source_pk`. Log-and-continue.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** (`feat(tcv): generation pipeline events`).

---

### Task 5: Lifecycle & validation events (contentregistry / validationlab)

**Files:**
- Modify: `orchestrator/internal/contentregistry/` transition path (where lifecycle `content_version_events` rows are written, alongside `recordCoverageIfExecutable`)
- Modify: `orchestrator/internal/validationlab/orchestrator.go` (the `content_validations` EXECUTION insert + the `→VALIDATED`/`→DRAFT` resolve)
- Test: `orchestrator/internal/contentregistry/tcv_lifecycle_events_test.go`, `orchestrator/internal/validationlab/tcv_validation_events_test.go`

**Interfaces:**
- Consumes: Task 2 writer; existing `Transition(...)`, the `content_validations` writer, `scenario_runs.execution_kind`.
- Produces: `validation_dispatched` (→VALIDATING), `validation_resulted` (each EXECUTION `content_validations` row, payload `{outcome, run_id}`), `validated_coverage` (→VALIDATED, write-once per version), `published_executable` (→PUBLISHED/PUBLISHED_LOCAL), `superseded`/`retired`/`rejected`. All carry `content_version_id`; validation events carry `validation_run_id` and require the EXECUTION row's `run_id` to join a `factory_validation` run.

- [ ] **Step 1: Write the failing test** `TestValidationEvents_TwoFailThenPassOneCoverage` (acceptance 4): two EXECUTION FAIL cycles then a PASS → exactly one `validated_coverage`, `event_time` = the `→VALIDATED` transition time; two `validation_resulted` with `payload->>'outcome'` FAIL and one PASS.
- [ ] **Step 2: Run** it — Expected: FAIL.
- [ ] **Step 3: Implement** the validation emits in `validationlab`/transition path; derive `validation_run_id` from the EXECUTION row's `run_id`; only emit validation events when that `run_id` joins `scenario_runs.execution_kind='factory_validation'`.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Write the failing tests:** `TestPublishedLocal_NoValidatedCoverage` (acceptance 5 — hand-authored `DRAFT→PUBLISHED_LOCAL` emits `published_executable`, no `validated_coverage`); `TestValidation_VersionScoped` (acceptance 6 — validating version A emits no `validated_coverage` for version B of the same threat); `TestCustomerRun_NoValidationEvent` (acceptance 7 — a non-`factory_validation` run produces no validation event); `TestValidationResulted_NoDataNotCoverage` (Review Focus — EXECUTION outcome `NO_DATA`/`ERROR` records `validation_resulted` but no `validated_coverage`).
- [ ] **Step 6: Run** all four — Expected: FAIL (if the customer-run / NO_DATA tests already pass from Task-5 Step-3's `factory_validation` join guard, note that in the ledger and keep them).
- [ ] **Step 7: Implement** the lifecycle emits (`published_executable`, `superseded`, `retired`, `rejected`) on their transitions; ensure `validated_coverage` is keyed write-once per `content_version_id` and fires only on `→VALIDATED`.
- [ ] **Step 8: Write the failing test** `TestPhase2C_Unchanged` (acceptance 13): with the ledger wired, `tcv.Store.Metrics` and `tcv.AggregateMetrics` return the same results as before for a seeded threat (no 2C regression).
- [ ] **Step 9: Run** `go test ./internal/contentregistry/ ./internal/validationlab/ -run 'TestValidation|TestPublishedLocal|TestCustomerRun|TestPhase2C'` — Expected: PASS.
- [ ] **Step 10: Commit** (`feat(tcv): lifecycle + factory-validation pipeline events`).

---

### Task 6: Reconciler / backfill

**Files:**
- Create: `orchestrator/internal/tcv/reconcile.go`, `orchestrator/internal/tcv/reconcile_test.go`
- Modify: `orchestrator/cmd/server/main.go` (schedule `ReconcilePipelineEvents` on the existing periodic timer; one-shot at boot for backfill)

**Interfaces:**
- Produces: `func ReconcilePipelineEvents(ctx context.Context, pool *pgxpool.Pool) error` — re-derives events from `source_observations`, `content_generation_attempts`, `content_version_events`, `content_validations` (EXECUTION ⋈ factory_validation) via idempotent `RecordPipelineEvent`. Never emits `threat_eligible` (unreconstructable).

- [ ] **Step 1: Write the failing test** `TestReconcile_EmitsMissingContentCreated` (acceptance 8): seed a `content_generation_attempts` row with `outcome='created'` and NO corresponding ledger event; run `ReconcilePipelineEvents`; assert a `content_created` event now exists with `event_time` from the source; run it again → no duplicate (idempotent).
- [ ] **Step 2: Run** `go test ./internal/tcv/ -run TestReconcile_EmitsMissingContentCreated` — Expected: FAIL.
- [ ] **Step 3: Implement** `ReconcilePipelineEvents` (one SELECT-and-emit pass per source table, each `RecordPipelineEvent` idempotent).
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Write the failing test** `TestReconcile_NeverEmitsEligible` (Review Focus / §10): seed observation + cga rows but no `threat_eligible`; reconcile; assert zero `threat_eligible` events exist.
- [ ] **Step 6: Run** it — Expected: FAIL (if the implementation wrongly derives it) or PASS; make the derivation explicit either way.
- [ ] **Step 7: Implement/confirm** the omission of `threat_eligible` from reconciliation; wire the periodic + boot call in `main.go`.
- [ ] **Step 8: Run** `go test ./internal/tcv/ -run TestReconcile` — Expected: PASS.
- [ ] **Step 9: Commit** (`feat(tcv): pipeline-event reconciler and backfill`).

---

### Task 7: SLA projection

**Files:**
- Create: `orchestrator/internal/tcv/sla.go`, `orchestrator/internal/tcv/sla_test.go`

**Interfaces:**
- Consumes: `tcf_pipeline_events`.
- Produces:
  - `type Stage string` (`StageQueue`, `StageGeneration`, `StageValidation`, `StageEndToEnd`).
  - `func stageSeconds(events []Event) map[Stage]*int64` — pure; per spec §9 deltas; nil = open.
  - `type SLASegment struct { Source, ContentType string; Cohort string /* validated|failed|open */ ; N int; P50Seconds, P95Seconds *float64 }`
  - `type SLAReport struct { Segments []SLASegment; OpenCount int; OldestOpenSeconds *int64; Bottleneck Stage; IncompleteWindow bool }`
  - `func (s *Store) SLA(ctx context.Context, stage Stage, since time.Time) (SLAReport, error)`.

- [ ] **Step 1: Write the failing test** `TestStageSeconds_OpenAndMeasured` (pure): an event list with observed+eligible but no content_created yields `StageQueue` measured, `StageGeneration` nil (open), `StageValidation` nil; a full list yields all four measured with the exact second deltas.
- [ ] **Step 2: Run** `go test ./internal/tcv/ -run TestStageSeconds_OpenAndMeasured` — Expected: FAIL.
- [ ] **Step 3: Implement** `Stage`, `stageSeconds`.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Write the failing tests** (DB-backed, seed ledger rows directly):
  - `TestSLA_IndependentStagePopulations` (acceptance 14): a leg with queue-only events contributes to the queue percentile and is absent from generation/validation samples; queue `N` not reduced by it.
  - `TestSLA_ValidatedCohortOnly` (acceptance 15): P50/P95 computed over validated legs only; one failed + one open leg excluded from percentiles but counted in `failed`/`open` rates; `OpenCount` and `OldestOpenSeconds` set.
  - `TestSLA_PercentilesAndEmptySegment` (acceptance 9): correct P50/P95 on a seeded distribution; a segment with no legs reports `N=0`, not an error.
  - `TestSLA_BottleneckNamesLargestP95` (acceptance 10): on a seeded skew, `Bottleneck` = the stage with the largest P95.
  - `TestSLA_IncompleteWindowExcludedAndFlagged` (acceptance 11): a leg with `threat_observed` but no `threat_eligible` is excluded from P50/P95 and sets `IncompleteWindow=true`.
  - `TestSLA_TwoLegThreatNotMerged` (Review Focus): a threat with both `emulates` and `generated_for` legs produces two independent rows, no double-count/merge.
  - `TestSLA_MonotoneAfterDemotion` (acceptance 16): a leg demoted/retired after `validated_coverage` keeps its end-to-end measurement.
- [ ] **Step 6: Run** `go test ./internal/tcv/ -run TestSLA` — Expected: FAIL.
- [ ] **Step 7: Implement** `SLA` using `percentile_cont(0.5|0.95) WITHIN GROUP (...)` over per-leg stage durations, segmented by source + `relationship_kind`, cohort-bucketed, with open-cohort and completeness computed as spec §9/§15.
- [ ] **Step 8: Run** — Expected: PASS.
- [ ] **Step 9: Commit** (`feat(tcv): internal SLA projection (stage P50/P95, bottleneck)`).

---

### Task 8: SLA API endpoint + RBAC

**Files:**
- Create: `orchestrator/internal/api/factory_sla_handlers.go`, `orchestrator/internal/api/factory_sla_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (register `GET /api/intel/factory/sla`), and the `routeMatrix` (RBAC-drift trap)

**Interfaces:**
- Consumes: `tcv.Store.SLA`.
- Produces: `GET /api/intel/factory/sla?stage=&since=` → JSON `SLAReport`; RBAC tier matching the other intel/factory read endpoints.

- [ ] **Step 1: Write the failing test** `TestFactorySLAHandler_ReturnsReport`: seeded ledger → handler returns 200 with the `SLAReport` JSON (segments, bottleneck, open cohort).
- [ ] **Step 2: Run** `go test ./internal/api/ -run TestFactorySLAHandler_ReturnsReport` — Expected: FAIL.
- [ ] **Step 3: Implement** the handler + route registration.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Write the failing test** `TestRBACMatrix_NoDrift` already exists — add the new route's expected matrix entry so it passes; run it to confirm it currently FAILS without the entry.
- [ ] **Step 6: Run** `go test ./internal/api/ -run TestRBACMatrix_NoDrift` — Expected: FAIL (route not in matrix).
- [ ] **Step 7: Implement** the `routeMatrix` entry for `GET /api/intel/factory/sla`.
- [ ] **Step 8: Run** `go test ./internal/api/ -run 'TestFactorySLAHandler|TestRBACMatrix_NoDrift'` — Expected: PASS.
- [ ] **Step 9: Commit** (`feat(tcv): factory SLA read endpoint + RBAC`).

---

## Notes for the executor

- `internal/api` full suite can hang in this environment — verify with scoped `-run` names; treat a bare full-suite hang as the known artifact, not a regression (see TCF notes).
- Wire-site line numbers in this plan are from a near-main worktree; build off `main` and locate the symbols (`resolvePendingClaims`, `recordAttempt`, `Transition`, `validationlab.Orchestrator` resolve) if line numbers drift.
- Tests needing Docker/Postgres use `GOTMPDIR=C:/basbuild/gotmp-tcf` and `-p 1`/`-p 2` per host memory.
