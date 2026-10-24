# DB Simulation Run Experience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator can register a database target, validate it, start a database simulation run from the console, watch it, and read an evidence-backed result and printable report, with `dbsim_runs` as the single record.

**Architecture:** dbsim-owned job table + service; dispatch of the signed `command_scenario` to the target's bound agent through the existing hub with NO `scenario_runs` row; a small ingest hook at the top of `SubmitScenarioResult` for dbsim job ids only; results graded by the existing `dbrun.Evaluate` and saved by `SaveDBSimRun`; own report endpoint and console page. All logic is in pure, fake-testable packages; `internal/api` and `internal/db` stay thin.

**Tech Stack:** Go (orchestrator + agent modules), PostgreSQL via pgx, existing WebSocket hub, vanilla-JS SPA built with esbuild (Node in Docker).

**Spec:** `docs/superpowers/specs/2026-10-24-dbsim-run-experience-design.md` (approved 2026-10-24). Read it first, especially sections 5, 6, 6.8 and 8. Engine background: `docs/dbsim-mastery-qa-log.md`, `docs/dbsim-operator-guide.md`, ledger rulings in `.superpowers/sdd/2026-10-22-dbsim-database-security-simulation/progress.md` (R-T..R-AT).

## Global Constraints

- Machine limits: `GOMAXPROCS=2`, `go test -p 1`, touched packages only. Orchestrator `internal/api`, `internal/db`, `internal/verification` test mains start Docker and cannot run on this host: build and vet them only, and list the exact Docker-host commands in every report.
- Sonnet only for every subagent. Local commits with trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Never push; the owner pushes.
- Do not weaken agent gate B5, any lab/client gate, the client-mode layers, or the import rule R-AG (`internal/dbsim`, `internal/db`, `internal/testutil` never import `detectverify`, `dbcorrelate` or `dbrun`; `internal/dbsim/dbjobs` MAY import `dbrun`, `dbbuild`, `dbadmin` but nothing in the guarded packages may import `dbjobs`). Check with `go vet ./internal/verification/...` and the importguard test.
- No secret ever reaches the server, logs, job rows, notes or API responses. Credential references (`dbcred:<name>`) only.
- No `scenario_runs` row is ever created for a dbsim run. The overall score, audit pack and `FleetRisk` must stay untouched.
- Verdicts are PASS/FAIL/ERROR/SKIPPED; ERROR, SKIPPED and unverifiable are never counted as passes. Remediation text only for an established failure, worded conditionally.
- Defaults from the spec: job deadline = 90 s x selected scenarios + 120 s (configurable); at most one active job per target and per agent (409); identity-check validity 24 h (`dbsim.DefaultIdentityCheckMaxAge`); lab run permission `CanRunScenario`; client-mode runs and identity checks Admin only; cancel uses the run permission; report/list/detail use `CanViewDBSim`.
- Anything unverified live is labelled UNVERIFIED in docs and reports. Scenario files are not edited by this plan (so no re-signing); if one must be, re-sign with `orchestrator/scripts/signer.go` and check no `TAMPER` line names `scenarios\dbsim-db*`.

## Review Focus

1. A result submission whose run id is NOT a dbsim job must behave exactly as before (including the deliberate no-op accept for an unknown run id). Pin with a regression test in Task 6.
2. A duplicate or replayed agent result must not create a second row, flip a finished job, or upgrade a `partial` to `completed` with fewer scenarios graded (Task 5).
3. An agent that reports a different `agentId` than the job's bound agent must be rejected (Task 5/6), and a result for a job already `cancelled` or `failed` must be ignored, not saved as a pass.
4. A target whose agent, host, credential reference or expected identity changes after a passed check, or whose check is older than the validity period, must refuse client-mode runs (Task 3/4).
5. A missing, offline or busy agent must produce a clear failed job (never a hang): dispatch failure, deadline expiry with zero rows (`failed`) and with some rows (`partial`) (Task 4/7).

---

### Task 1: Dispatch spike (throwaway, decides the design)

**Files:**
- Create (build tag `dbsim_spike`, NOT merged to the main line): `orchestrator/internal/api/dbsim_spike.go` and `orchestrator/internal/api/dbsim_spike_hook.go`
- Create: `docs/dbsim-run-spike-findings.md` (kept)

**Interfaces:**
- Consumes: `dbbuild.BuildSteps(ctx, sc *scenario.Scenario, opt dbbuild.Options) ([]scenario.ScenarioStep, error)`, `h.hub.SendToAgent(agentID string, models.WSMessage) bool`, `scenario.ScenarioCommand`, `SubmitScenarioResult`.
- Produces: a recorded decision: PROCEED (design section 6 stands) or FALLBACK (dedicated command type/route; stop and return to the owner before Task 2).

- [ ] **Step 1: Implement under `//go:build dbsim_spike`** a handler `POST /api/dbsim-spike/run` (Admin only, body `{agentId, targetId, scenarioId}`) that builds steps for one lab scenario with `dbbuild.BuildSteps` (target resolved via `DBSimTargetResolver`), sends `command_scenario` with a fresh run id and NO `scenario_runs` insert, and records the run id in an in-memory map; plus a hook at the top of `SubmitScenarioResult` that, if the run id is in the map, logs the decoded results (probe ids, exit codes, `dbProbe` present) and returns 200 without touching the database.
- [ ] **Step 2: Build with and without the tag.** Run `go build ./...` and `go build -tags dbsim_spike ./...` in `orchestrator`; both must succeed and the untagged build must not contain the handler.
- [ ] **Step 3 (owner/staging):** On staging with the lab up and an agent bound next to the lab database, trigger DB-01 and DB-05 on PostgreSQL and MySQL through the spike. Record in `docs/dbsim-run-spike-findings.md`: did the agent execute the steps with no run row; did `POST /api/scenarios/events` calls arrive (check `run_events`) and reach the browser relay; did the result MAC and agent-id checks pass; did the agent's run-limit/`ExecutionAttempt` bookkeeping object; what happens when a normal scenario run is active on the same agent at the same time.
- [ ] **Step 4: Decision gate.** If every point above is fine: record PROCEED, delete the spike files, commit only the findings doc. If anything fails: record FALLBACK with the exact failure and STOP; the controller returns to the owner.
- [ ] **Step 5: Commit** the findings doc: `git add docs/dbsim-run-spike-findings.md && git commit -m "docs(dbsim): run dispatch spike findings"`.

### Task 2: Production expectations table and `MetaFor`

**Files:**
- Create: `orchestrator/internal/dbsim/expectations.go`, `orchestrator/internal/dbsim/expectations_test.go`
- Create: `orchestrator/internal/dbsim/dbbuild/meta.go`, `orchestrator/internal/dbsim/dbbuild/meta_test.go`
- Modify: `orchestrator/internal/dbsim/dbrun/support_test.go` (replace `labExpectationFor`/`labMeta` bodies with calls to production), `orchestrator/internal/dbsim/dbrun/e2e_test.go` only if needed to compile.

**Interfaces:**
- Produces: `type Expectation struct{ ExpectedPrevention string; ExpectDetection, ExpectAudit, ExpectAuditConfig, RequireObservation, RequirePolicyDiff, ExpectClassification bool }`; `func ExpectationFor(scenarioID, probeID string) (Expectation, bool)` (false for unknown scenario/probe pairs: fail closed); `func MetaFor(sc *scenario.Scenario, spec dbsim.DBProbeSpec) (dbsim.ScenarioMeta, error)` in `dbbuild` (error for an unknown scenario id, a scenario whose product line is not `dbsim`, or a probe without an expectation).

- [ ] **Step 1: Write failing tests.** `TestExpectationForPinsTheLiveVerifiedGrading`: table over all 11 shipped scenario/probe pairs asserting the exact values the staging runs graded with (copy from `labExpectationFor`: default allow+detection; `read_audit_config` no detection + auditCfg; `read_restricted_table`, `try_disable_audit`, `try_write_fixture` deny; `check_export_privileges` and `auth_after_revoke` deny, no detection; `read_grants` RequireObservation and RequirePolicyDiff; `dbsim-db04-audit-coverage`/`read_roles` ExpectAudit; `read_classified_fixture` ExpectClassification). `TestExpectationForUnknownFailsClosed`. `TestMetaForRejectsNonDBSimScenario`, `TestMetaForFillsIdentityFromSpec` (ID, Engine, TargetID, Mode from the spec/scenario; Version from the scenario).
- [ ] **Step 2: Run** `go test -count=1 -p 1 ./internal/dbsim/ ./internal/dbsim/dbbuild/` expecting compile failure/FAIL.
- [ ] **Step 3: Implement** the table (move, do not reinvent, the values in `dbrun/support_test.go`) and `MetaFor`; control objective, preconditions, synthetic-data manifest and action text come from the signed scenario's own fields where they exist, otherwise fixed text per probe.
- [ ] **Step 4: Point the test helper at production** so the live-verified E2E and unit grading run through the same code. Run `go test -count=1 -p 1 ./internal/dbsim/...` (all packages) expecting PASS and `go vet -tags dbsim_e2e ./internal/dbsim/...` clean.
- [ ] **Step 5: Commit** `feat(dbsim): production scenario expectations and MetaFor`.

### Task 3: Target agent binding

**Files:**
- Modify: `orchestrator/internal/dbsim/targetreg.go` (+ `targetreg_test.go`, `targetreg_fix1_test.go`), `orchestrator/internal/db/dbsim_targets_store.go`, `orchestrator/internal/api/dbsim_handlers.go`, `orchestrator/internal/dbsim/dbadmin/service.go`

**Interfaces:**
- Consumes: `dbsim.TargetRegistration`, `TargetRecord.SameConfig`.
- Produces: `TargetRegistration.AgentID string` (required, validated in `Normalize` as a non-empty id matching the agent id charset used elsewhere); `SameConfig` includes `AgentID`; store column `agent_id text NOT NULL DEFAULT ''` added with `ALTER TABLE dbsim_targets ADD COLUMN IF NOT EXISTS agent_id` inside `EnsureDBSimTargetSchema` (existing rows without an agent fail closed: cannot be run until re-registered); `dbadmin.AgentDirectory interface{ Exists(ctx context.Context, agentID string) (bool, error) }` injected into `Service` and checked on registration; `dbsim.Target.AgentID string`.

- [ ] **Step 1: Failing tests (pure):** `TestRegisterRequiresAgentID`, `TestRegisterRejectsUnknownAgent` (fake `AgentDirectory`), `TestAgentChangeInvalidatesIdentityCheck` (SameConfig false when AgentID differs), `TestLegacyTargetWithoutAgentCannotRun` (Authorize refuses). Docker store test (written, not run here): round-trip of `agent_id` and the migration on an existing table.
- [ ] **Step 2: Run** `go test -count=1 -p 1 ./internal/dbsim/...` expecting FAIL.
- [ ] **Step 3: Implement** the field, validation, `SameConfig`, resolver mapping to `dbsim.Target.AgentID`, store column and migration, request/response JSON (`agentId`), and the directory check (implemented in `internal/api` over the existing agents table).
- [ ] **Step 4: Verify:** the same tests PASS; `go build ./...` and `go vet ./internal/api/ ./internal/db/` clean.
- [ ] **Step 5: Commit** `feat(dbsim): bind each target to its agent`.

### Task 4: Job model, store and start/cancel service

**Files:**
- Create: `orchestrator/internal/dbsim/runjob.go` (+ `runjob_test.go`), `orchestrator/internal/dbsim/dbjobs/service.go` (+ `service_test.go`), `orchestrator/internal/db/dbsim_jobs_store.go` (+ `dbsim_jobs_store_test.go`, Docker)

**Interfaces:**
- Identity checks are jobs too (they run the read-only probe `check_readonly_identity` on the bound agent): `type JobKind string` with `JobKindRun` and `JobKindIdentityCheck`; `RunJob.Kind JobKind`; `dbbuild.BuildIdentityCheckStep(ctx context.Context, t dbsim.Target, opt dbbuild.Options) (scenario.ScenarioStep, dbsim.DBProbeSpec, error)` (one signed read-only step for the target, same gates as `BuildSteps`, client or lab mode per the target); `(*dbjobs.Service).StartIdentityCheck(ctx, a dbadmin.Actor, targetID string) (RunJob, error)` (Admin only; the one-active-job-per-target/agent rule applies). The existing synchronous `dbadmin.Service.RunIdentityCheck`/`CheckRunner` contract is replaced by this asynchronous job: `POST /api/dbsim-targets/{id}/identity-check` now returns 202 `{runId}` and the result is recorded by Task 5's ingest.
- Produces in `dbsim`: `type JobStatus string` with constants `JobPending, JobRunning, JobCompleted, JobFailed, JobPartial, JobCancelled`; `func (s JobStatus) CanTransitionTo(next JobStatus) bool` (pending->running|failed|cancelled; running->completed|failed|partial|cancelled; terminal states final); `type PlannedStep struct{ ScenarioID string; Index int; Spec DBProbeSpec }`; `type RunJob struct{ ID, TargetID, AgentID string; Mode ExecMode; ScenarioIDs []string; Plan []PlannedStep; Status JobStatus; Reason, CreatedBy, LabConfirmation string; CreatedAt, StartedAt, Deadline time.Time }`; `func DeadlineFor(created time.Time, nScenarios int) time.Time`.
- Produces in `dbjobs`: `type JobStore interface{ Create(ctx, RunJob, dbadmin.AuditEntry) error; Get(ctx, id string) (RunJob, error); Transition(ctx, id string, from []JobStatus, to JobStatus, reason string, audit dbadmin.AuditEntry) (bool, error); ActiveForTarget(ctx, targetID string) (bool, error); ActiveForAgent(ctx, agentID string) (bool, error); Expired(ctx, now time.Time) ([]RunJob, error) }`; `type Dispatcher interface{ Dispatch(ctx context.Context, agentID string, cmd scenario.ScenarioCommand) (sent bool) }`; `type Service struct` with `Start(ctx, a dbadmin.Actor, req StartRequest) (RunJob, error)` and `Cancel(ctx, a dbadmin.Actor, runID string) error`; `type StartRequest struct{ TargetID string; ScenarioIDs []string; LabConfirmation string }`; sentinel errors `ErrBusy` (409), `ErrNotPermitted` (403), `ErrAgentOffline` (503), `ErrTargetNotReady` (409).
- Store guarantee: a partial unique index makes a second active (pending/running) job for the same target or agent impossible even under a race; `Create` returns `ErrBusy` on violation.

- [ ] **Step 1: Failing tests (pure, fakes):** `TestJobStatusTransitions`; `TestDeadlineFor` (3 scenarios => created + 390 s); `TestStartLabRunRequiresTypedTargetNameConfirmation`; `TestStartClientRunRequiresAdminGateAndFreshIdentityCheck`; `TestStartUsesTargetModeNeverRequestMode`; `TestStartRefusesBusyTargetAndBusyAgent` (409); `TestStartMarksFailedWhenAgentOffline` (job ends `failed` with reason, audit written); `TestStartStoresPlanWithMarkersAndNoSecrets` (assert plan JSON contains no `password`/`secret`, only the credential reference); `TestCancelSendsCommandCancelAndMarksCancelled`; `TestCancelRequiresRunPermission`.
- [ ] **Step 2: Run** `go test -count=1 -p 1 ./internal/dbsim/ ./internal/dbsim/dbjobs/` expecting compile failure.
- [ ] **Step 3: Implement** the types, `Service` (uses `dbadmin.Service.Gate()`, `dbsim.Target`/`TargetRecord.ToTargetAt`, `dbbuild.BuildSteps`, `MetaFor` for validation that every selected scenario has expectations, the RunExpiry = job deadline) and the Postgres store with the unique partial indexes and guarded `UPDATE ... WHERE status = ANY($from)` transitions, each in the audit transaction helper `withDBSimAuditTx`. `EnsureDBSimJobSchema` is idempotent and `CREATE ... IF NOT EXISTS` only.
- [ ] **Step 4: Verify** the pure tests PASS; `go build ./...`, `go vet ./internal/dbsim/... ./internal/db/` clean; Docker-host command recorded: `go test -p 1 -run DBSimJob ./internal/db/`.
- [ ] **Step 5: Commit** `feat(dbsim): run job model, store and start/cancel service`.

### Task 5: Result ingest

**Files:**
- Create: `orchestrator/internal/dbsim/dbjobs/ingest.go`, `orchestrator/internal/dbsim/dbjobs/ingest_test.go`

**Interfaces:**
- Consumes: `dbrun.Evaluate(ctx, conn detectverify.Connector, in dbrun.StepInput) (dbrun.Evaluation, error)`, `dbrun.AgentExec`, `db.SaveDBSimRun` via an interface.
- Produces: `type RunSink interface{ Save(ctx context.Context, rec RunRecord) (duplicate bool, err error) }` (`RunRecord` mirrors `db.DBSimRun`); `type Submission struct{ RunID, AgentID string; Partial bool; Results []dbrun.AgentExec }`; `func (s *Service) Ingest(ctx context.Context, sub Submission) (handled bool, err error)` where `handled=false` means "not a dbsim job id, caller continues as before".

- Identity-check jobs: `Ingest` routes a `JobKindIdentityCheck` submission to `type IdentityRecorder interface{ Record(ctx context.Context, jobTarget dbsim.TargetRecord, res dbsim.DBProbeResult) error }` which runs `dbsim.EvaluateReadOnlyIdentity`, then the existing version-bound, audited `SaveIdentityCheck` (a changed or superseded target records nothing). A failed or malformed result records a FAILED check, which withdraws an earlier pass; it never records a pass.
- [ ] **Step 1: Failing tests (fakes for JobStore, RunSink, connector):** also `TestIngestIdentityCheckPassRecordsVersionBoundPass`, `TestIngestIdentityCheckMalformedResultRecordsFailure`, `TestIngestIdentityCheckForChangedTargetRecordsNothing`; `TestIngestUnknownRunIDIsNotHandled`; `TestIngestGradesEachScenarioAndCompletesJob` (3 scenarios => 3 saved rows, job `completed`); `TestIngestPartialWhenAgentReportsPartialOrRowsMissing` (job `partial`, saved rows kept); `TestIngestDuplicateSubmissionIsIdempotent` (no second row, status unchanged); `TestIngestIgnoresResultForCancelledOrFailedJob`; `TestIngestRejectsAgentMismatch` (returns handled=true and an error, nothing saved); `TestIngestNeverGradesFromAgentVerdict` (marker/probe id taken from the job plan, not the agent answer); `TestIngestFixtureCleanupUnverifiedGradesError` (existing safety rule survives); `TestIngestErrorsAreRedacted`.
- [ ] **Step 2: Run** `go test -count=1 -p 1 ./internal/dbsim/dbjobs/` expecting FAIL.
- [ ] **Step 3: Implement** `Ingest`: load job, map result i to `Plan[i]`, build `StepInput` with `MetaFor`, target host/IPs from the resolved target, the lab detection window and skew from configuration constants, `ClassificationRuleName = dbsim.LabClassificationRuleName` for lab mode; call `Evaluate`; save each; then guarded status transition. Alert source: connector from an injected `ConnectorFactory`; with none configured, correlation is skipped and Telemetry stays Unverifiable (never a miss).
- [ ] **Step 4: Verify** PASS; `go vet ./internal/verification/...` and importguard unchanged.
- [ ] **Step 5: Commit** `feat(dbsim): grade and save run results from agent submissions`.

### Task 6: API handlers, routes, ingest hook

**Files:**
- Modify: `orchestrator/internal/api/dbsim_handlers.go`, `orchestrator/internal/api/routes.go`, `orchestrator/internal/api/handlers.go` (hook at the top of `SubmitScenarioResult`, after MAC verification and before the unknown-run no-op), `orchestrator/internal/api/rbac_matrix_test.go`, `orchestrator/internal/api/product_gate_test.go`, `orchestrator/cmd/server/main.go`
- Test: `orchestrator/internal/api/dbsim_runs_handlers_test.go`

**Interfaces:**
- Consumes: `dbjobs.Service`.
- Produces: `POST /api/dbsim-runs` (body `{targetId, scenarioIds, labConfirmation}` -> 202 `{runId}`), `POST /api/dbsim-runs/{runId}/cancel`, `GET /api/dbsim-jobs/{runId}` (status, per-scenario progress, reason), existing `GET /api/dbsim-runs` and `/{id}` unchanged; `Handler.WithDBSimJobs(*dbjobs.Service)`; error mapping `ErrBusy`->409, `ErrNotPermitted`->403, `ErrAgentOffline`->503, `ErrTargetNotReady`->409; `POST /api/dbsim-targets/{id}/identity-check` becomes the asynchronous `StartIdentityCheck` job from Task 4 (202 `{runId}`; ends the 501 and replaces `WithDBSimCheckRunner`; update `dbsim_handlers_test.go` accordingly).

- [ ] **Step 1: Failing tests:** pure handler tests for 400/403/409/503 mapping and request-size limits (`&Handler{}` paths that never touch the DB); `TestSubmitScenarioResultUnknownRunIDStillNoOp` and `TestSubmitScenarioResultNormalRunUnchangedByDBSimHook` (Docker host, written here); RBAC matrix rows for the three new routes (run: `CanRunScenario` lab / Admin client; cancel: same; jobs read: `CanViewDBSim`).
- [ ] **Step 2: Run** `go test -count=1 -p 1 -run DBSim ./internal/api/` is NOT runnable here; run `go build ./... && go vet ./internal/api/` and the pure tests in `dbjobs`.
- [ ] **Step 3: Implement** handlers, routes (inside the existing gated prefixes `/api/dbsim-runs` and add `/api/dbsim-jobs` to `product_gate.go` and its test), the hook (`if handled, err := h.dbsimJobs.Ingest(...); handled { respond; return }`, nil service => skipped), actor extraction as the existing dbsim handlers do, and the startup wiring (service construction, `EnsureDBSimJobSchema`).
- [ ] **Step 4: Verify** build/vet clean; list the Docker-host commands: `go test -p 1 -run 'DBSim|RBACMatrix|ProductGate|NoDrift|SubmitScenarioResult' ./internal/api/`.
- [ ] **Step 5: Commit** `feat(dbsim): run, cancel and job-status API with guarded result ingest`.

### Task 7: Reaper and recovery

**Files:**
- Create: `orchestrator/internal/dbsim/dbjobs/reaper.go`, `orchestrator/internal/dbsim/dbjobs/reaper_test.go`
- Modify: `orchestrator/cmd/server/main.go` (start alongside the existing `ReapNeverStartedRuns`/`ReapAbandonedRuns` poll tick)

**Interfaces:**
- Produces: `func (s *Service) Reap(ctx context.Context, now time.Time) (int, error)`: for each expired job, `failed` with reason when no rows were saved for it, `partial` when some were; running jobs whose agent is offline are handled the same way; guarded transitions only (never clobbers a job that finished meanwhile); `AgentPresence interface{ Online(agentID string) bool }`.

- [ ] **Step 1: Failing tests:** `TestReapExpiredPendingBecomesFailed`, `TestReapExpiredRunningWithRowsBecomesPartial`, `TestReapDoesNotTouchFinishedJob` (race: transition guarded), `TestReapOfflineAgentBeforeDeadlineBecomesPartialOrFailed`, `TestReapWritesAudit`.
- [ ] **Step 2: Run** `go test -count=1 -p 1 ./internal/dbsim/dbjobs/` expecting FAIL.
- [ ] **Step 3: Implement** `Reap` and wire the poller; on startup, run one `Reap` so restarts recover orphaned jobs.
- [ ] **Step 4: Verify** PASS; `go build ./...` clean.
- [ ] **Step 5: Commit** `feat(dbsim): reap expired and orphaned run jobs`.

### Task 8: Summary and printable report

**Files:**
- Create: `orchestrator/internal/dbsim/summary.go` (+ test), `orchestrator/internal/reporting/dbsim_report.go` (+ `dbsim_report_test.go`)
- Modify: `orchestrator/internal/api/dbsim_handlers.go`, `orchestrator/internal/api/routes.go`, RBAC matrix

**Interfaces:**
- Produces: `type Summary struct{ PreventionBlocked, PreventionAssessable, DetectionCaught, DetectionAssessable, UnableToAssess int; ResponseTested bool }`; `func Summarize(reports []StoredReport) Summary` (prevention assessable = scenarios whose prevention dimension is pass or fail; detection assessable = detection pass or fail; `unverifiable`, `skipped`, `not_expected`, ERROR and SKIPPED results never enter a numerator and ERROR/SKIPPED count in UnableToAssess; response is always "not tested"); `func BuildDBSimReport(r db.DBSimRun-equivalent StoredReport, opts) (string, error)` returning HTML via `html/template`; `GET /api/dbsim-runs/{id}/report` (`text/html`, `CanViewDBSim`); fixed remediation texts keyed by scenario id and failing dimension, emitted only when that dimension is `fail` and worded conditionally unless evidence names the grant/setting.

- [ ] **Step 1: Failing tests:** `TestSummarizeUsesSeparateDenominators`, `TestSummarizeNeverCountsErrorSkippedOrUnverifiedAsPass`, `TestReportRendersEveryDimensionState` (pass, fail, not_expected, skipped, unverifiable each appear as themselves, unlike the phishing builder), `TestReportShowsLimitationsConfidenceAndAlertSourceUnavailable`, `TestReportRemediationOnlyOnEstablishedFailure`, `TestReportEscapesEvidence` (HTML-escaped statements/aliases).
- [ ] **Step 2: Run** `go test -count=1 -p 1 ./internal/dbsim/ ./internal/reporting/ -run 'Summar|DBSimReport'` expecting FAIL (reporting tests may need `-short` if its TestMain wants Docker: check `internal/reporting/testmain_test.go`).
- [ ] **Step 3: Implement** summary, template and handler (mirror `GetPhishingRunReport`).
- [ ] **Step 4: Verify** PASS; build/vet clean.
- [ ] **Step 5: Commit** `feat(dbsim): run summary and printable report`.

### Task 9: Console

**Files:**
- Create: `orchestrator/web/src/features/dbsim.js`, `orchestrator/web/src/features/dbsim-view.js` (pure describe functions), `orchestrator/web/tests/unit/dbsim-view.test.mjs`
- Modify: `orchestrator/web/index.html` (section + nav), `orchestrator/web/src/core/actions.js` (ACTIONS entries), test baselines (smoke/visual) and the integrity manifest as the repo's build requires

**Interfaces:**
- Consumes: the Task 6/8 endpoints and the existing target endpoints; `describeRun(report)`, `describeSummary(summary)`, `describeScenarioRow(report)` as pure functions returning plain objects; no `innerHTML` with server data (repo CSP rules: no inline styles/handlers).

- [ ] **Step 1: Failing Node unit tests** for the pure functions: badge text for each of the five dimension states, "unable to assess" grouping, summary denominators, conditional remediation display, "alert source unavailable" vs "missed", lab-only/unsupported marking, honest empty and error states.
- [ ] **Step 2: Run** `node --test tests/unit/dbsim-view.test.mjs` expecting FAIL (Node via the repo's `tools/node.sh` on the Docker host).
- [ ] **Step 3: Implement** the screens from spec section 7: landing, targets (credential-reference field only, validate, status), test selection, progress (poll `GET /api/dbsim-jobs/{runId}`), results (layout A), scenario detail, report link.
- [ ] **Step 4: Verify on a Docker-capable host:** `npm run lint`, `npm test`, `npm run build`, smoke and visual runs; open the page in a browser against staging and attach screenshots. UNVERIFIED until then.
- [ ] **Step 5: Commit** `feat(dbsim): console page for targets, runs and results`.

### Task 10: Staging proof and documentation

**Files:**
- Modify: `docs/dbsim-operator-guide.md`, `docs/dbsim-mastery-qa-log.md`, `lab/dbsim/E2E.md`

- [ ] **Step 1 (owner/staging):** With the new build deployed on staging, from the console register the lab PostgreSQL and MySQL targets (agent-bound), run the identity check, start a lab run of all eleven scenarios on each engine, and compare every scenario's verdict and dimensions with the scripted E2E results of 2026-10-23 (all PASS except DB-02 read_grants ERROR by design). Run the independent cleanup check afterwards. Record outputs.
- [ ] **Step 2:** Test cancel mid-run, agent stopped mid-run (job becomes `partial`/`failed` via the reaper), and a second run while one is active (409).
- [ ] **Step 3: Document** the console workflow, the run API, the job lifecycle and what is verified live versus not, with exact commands for the Docker-host test runs; update the QA log and the operator guide's limitations.
- [ ] **Step 4: Commit** `docs(dbsim): run experience guide and staging results`.
