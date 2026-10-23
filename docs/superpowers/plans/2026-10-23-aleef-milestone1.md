# Aleef Milestone 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Aleef, a deterministic generator-and-verifier that derives API tests from an OpenAPI description, runs them through the existing API BAS runner, and reports candidate and verified business-logic and authorization flaws, proven on an independently authored held-out benchmark.

**Architecture:** New packages under `orchestrator/internal/aleef/`. A model importer reads an OpenAPI document; a property library and generator emit `contract.Scenario` values; an adapter runs them with `apibas/runner`; a verifier alone promotes candidates to verified findings; separate Postgres tables hold results. A synthetic bank API (clean skeleton plus sealed defects) is the benchmark target.

**Tech Stack:** Go (module `github.com/audspect/bas`), `net/http/httptest`, pgx/Postgres, `gopkg.in/yaml`, existing `internal/apibas/*`.

**Spec:** `docs/superpowers/specs/2026-10-23-aleef-milestone1-design.md` (sections 5 and 10 and 11 govern; section 10 overrides earlier text).

## Global Constraints

- Pass criteria: at least 6 of 8 held-out flaws verified (75%); 0 verified findings on fixed builds; 3 consecutive reproductions from fresh objects; owner control and negative control pass for every verified finding; saved regression test per verified finding.
- Production testing is refused in Milestone 1. Environment class `uat` or `lab` only.
- The generator, model, property and verify packages must not import `internal/aleef/bank` or anything under it, and must not read hidden labels. An import-graph test enforces this (Task 3).
- Seeded-defect code (H1-H8 trigger conditions) is written by the owner or Zain, never by the implementer, and is not read by the implementer. The implementer writes only the clean skeleton, the fixed build, the OpenAPI document and the policy hook.
- Reports say "new to Audspect". The word "zero-day" appears nowhere in product output; `prior_knowledge` defaults to `not_checked`.
- No LLM in Milestone 1. Generation is deterministic for a given (model, seed).
- Aleef is a separate product line, outside the Core/Advanced/Enterprise tier maps. Do not add it to `tierProductLines`.
- Until Task 11 lands, the executor refuses any non-loopback base URL.
- Reuse, do not fork: `contract.Scenario`, `runner.Runner`, `grade.Assess`, `runner/forbidden.go`, `targetscope.IsAuthorized`, the `injectionapproval` TTL pattern, `apibas_schema.go` conventions.
- Per repo convention: commit and push after each task; narrow `go test ./internal/aleef/...` per task; record QA in `docs/aleef-mastery-qa-log.md`; scoped git restores only.

## Review Focus

1. OpenAPI documents using `$ref`, `allOf`, missing `operationId`, or path-level parameters: importer must resolve or report "not modelled", never panic or guess.
2. An API that returns HTTP 200 with an error body (soft failure): the oracle must not count it as a successful unauthorized access.
3. A resource with no free-text field to carry a canary: leak tests fall back to structural comparison and are labelled lower-confidence.
4. 429 or repeated 5xx mid-run: the run halts (circuit breaker), leaves no uncleaned objects, and reports ERROR, not PASS.
5. Cleanup failure: the run ends `CLEANUP_FAILED`, lists orphaned object ids, and no finding from that run can become verified.

## File Structure

```
orchestrator/internal/aleef/
  model/        model.go openapi.go setup.go           # application model, importer, fixture build
  property/     property.go own.go role.go flow.go idem.go   # security properties and oracles
  generate/     generate.go vary.go                    # deterministic test generation
  novelty/      novelty.go                             # overlap with API BAS catalogue
  exec/         exec.go state.go cleanup.go            # runner adapter, state reader, compensating cleanup
  verify/       verify.go                              # only producer of verified findings
  safety/       engagement.go class.go limiter.go breaker.go
  store/        schema.go store.go                     # aleef_* tables
  export/       export.go                              # verified finding -> regression scenario
  bank/         bank.go policy.go openapi.json         # synthetic bank API, clean + fixed
  bank/sealed/  sealed_stub.go                         # build-tag stub; owner supplies sealed_defects.go
  bench/        bench.go labels.go                     # held-out evaluation harness
orchestrator/internal/api/aleef_handlers.go            # routes
orchestrator/cmd/aleef-bench/main.go                   # evaluation entry point
docs/aleef-benchmark-spec.md, docs/aleef-mastery-qa-log.md
```

---

### Task 1: Freeze the benchmark specification

**Files:** Create `docs/aleef-benchmark-spec.md`, `docs/aleef-mastery-qa-log.md`.

**Interfaces:** Produces the written contract Tasks 2, 12 and 14 cite.

- [ ] **Step 1:** Write `docs/aleef-benchmark-spec.md` containing, verbatim from spec section 10: the H1-H8 property table, pass criteria, and the sealed-defect rule. Add: the bank resources the clean API must expose (accounts, transactions, beneficiaries, payments with initiate/approve/settle, KYC documents with a primary and an alternate endpoint, `/v1` and `/v2` route sets), the label file format (`labels.json`: `[{"id":"H1","operation":"...","note":"..."}]`, held only by the owner, never committed to this repo), and the statement that the implementer has seen the property list but not trigger conditions.
- [ ] **Step 2:** Create `docs/aleef-mastery-qa-log.md` with a header and an empty "Evaluation" section.
- [ ] **Step 3:** Owner reviews the spec document. Do not proceed to Task 2 until the owner confirms it is frozen.
- [ ] **Step 4:** Commit `docs(aleef): freeze benchmark specification` and push.

---

### Task 2: Synthetic bank API, clean and fixed, with a policy hook

**Files:** Create `internal/aleef/bank/bank.go`, `policy.go`, `openapi.json`, `bank_test.go`; `internal/aleef/bank/sealed/sealed_stub.go`.

**Interfaces:**
- Produces:
  - `type Policy struct { CanReadAccount, CanModifyBeneficiary, ApprovalStillValid, DedupeIdempotency, CanSettle, CanApprove, CanReadDocument, LegacyAuthorize func(...) bool }` with the exact argument types chosen by the implementer and documented in `policy.go`.
  - `func FixedPolicy() Policy`: every function implements the correct rule.
  - `func New(cfg Config) (*Server, error)`; `Config{Policy Policy; Tokens map[string]Principal}`; `(*Server).Handler() http.Handler`.
  - `package sealed`: `func Policy(id string) (bank.Policy, bool)`. The stub, compiled without the `aleefsealed` tag, returns `(bank.FixedPolicy(), false)`.
- Consumes: nothing from earlier tasks.

- [ ] **Step 1: Write the failing conformance test** `TestFixedBankEnforcesAllProperties` in `bank_test.go`. For the fixed build, assert: customer B gets 403/404 on A's account, transaction, KYC document (primary and alternate endpoints) and `/v1` equivalents; B cannot PATCH A's beneficiary or payment; amount or beneficiary change after approval returns 409 and clears approval; a repeated `Idempotency-Key` returns the original transaction with no second row; settle without both required approvals returns 409; the initiating customer's approve call is refused when `dual_control=true`.
- [ ] **Step 2:** Run `go test ./internal/aleef/bank/ -run TestFixedBankEnforcesAllProperties` and confirm it fails (package missing).
- [ ] **Step 3:** Implement the bank per the signatures above. Handlers call the `Policy` functions at each decision point and nowhere else enforce those rules. Keep `openapi.json` free of labels, hints and defect names; it describes routes, schemas and security only. Serve it at `GET /openapi.json`.
- [ ] **Step 4:** Add `TestBankOpenAPIHasNoLabels`: the OpenAPI text contains none of the strings `vulnerable`, `defect`, `H1`..`H8`, `sealed`.
- [ ] **Step 5:** Run `go test ./internal/aleef/bank/...`; expect PASS.
- [ ] **Step 6:** Write `docs/aleef-benchmark-spec.md` addendum: exact `Policy` field list, and the instruction that the owner supplies `sealed_defects.go` (`//go:build aleefsealed`) returning defective policies for H1-H8 keyed by id. Do not write that file.
- [ ] **Step 7:** Commit `feat(aleef): synthetic bank API, fixed build and policy hook`; push.

---

### Task 3: Isolation guard (import graph and label access)

**Files:** Create `internal/aleef/isolation_test.go`.

**Interfaces:** Consumes the package list from the File Structure.

- [ ] **Step 1: Write the failing test** `TestGeneratorSideNeverImportsBenchmark`: using `go/build` or `golang.org/x/tools/go/packages`, assert that none of `aleef/model`, `property`, `generate`, `novelty`, `verify`, `export` transitively import `aleef/bank`, `aleef/bank/sealed` or `aleef/bench`.
- [ ] **Step 2:** Add `TestNoHiddenLabelReads`: grep the same packages' source for `labels.json` and the strings `H1`..`H8`; fail on any match.
- [ ] **Step 3:** Run; expect PASS now (packages are empty) and note the test must stay green for every later task.
- [ ] **Step 4:** Commit `test(aleef): enforce generator/benchmark isolation`; push.

---

### Task 4: Application model and OpenAPI importer

**Files:** Create `internal/aleef/model/model.go`, `openapi.go`, `model_test.go`, `testdata/*.json`.

**Interfaces:**
- Produces:
  - `type Operation struct { ID, Method, Path string; PathParams, QueryParams []Param; Body *Schema; Security []string; Class safety.Class }` (Class is set by the operator later; importer leaves `ClassUnknown`; define the `Class` type in `safety` in Task 11 and use a local string alias `type OpClass string` here to avoid an import cycle, then convert).
  - `type Param struct { Name string; In string; IsObjectID bool; Resource string }`
  - `type Model struct { Operations []Operation; Roles []string; NotModelled []string }`
  - `func Import(doc []byte) (Model, error)`.
- `IsObjectID` is true when the name matches `(?i)(^id$|_id$|Id$|ref$|number$)` or the path parameter sits under a collection segment.

- [ ] **Step 1: Write failing tests.** `TestImportResolvesRefs`, `TestImportReportsUnresolvableAsNotModelled`, `TestImportNeverPanicsOnMalformed` (table of truncated/empty/non-OpenAPI inputs), `TestImportMarksObjectIDParams`, `TestImportHandlesPathLevelParameters`, `TestImportOperationWithoutOperationIDGetsStableID` (id derived from method+path).
- [ ] **Step 2:** Run `go test ./internal/aleef/model/`; expect FAIL.
- [ ] **Step 3:** Implement `Import` with `encoding/json` over a minimal OpenAPI struct plus `$ref` resolution within `#/components`. Unknown constructs append to `NotModelled`; never guess.
- [ ] **Step 4:** Run tests; expect PASS. Run `TestGeneratorSideNeverImportsBenchmark`; expect PASS.
- [ ] **Step 5:** Commit `feat(aleef): application model and OpenAPI importer`; push.

---

### Task 5: Setup plan, ownership discovery and fixture build

**Files:** Create `internal/aleef/model/setup.go`, `setup_test.go`.

**Interfaces:**
- Consumes: `model.Model`.
- Produces:
  - `type Account struct { Name, CustomerID, TokenRef, Role string }`
  - `type SetupOp struct { OperationID string; Body map[string]any; Compensate string }` (operator-declared; `Compensate` names the compensating operation id).
  - `func BuildFixture(ctx context.Context, m Model, accounts []Account, setup []SetupOp, d Doer, runTag string) (fixture.Fixture, []CreatedObject, error)` where `Doer` is `interface{ Do(*http.Request) (*http.Response, error) }`, and `CreatedObject{Operation, ID, Owner, Compensate string}`.
  - Canary value format: `ALEEF-CANARY-<runTag>-<account>`; written into the first free-text string field of each created body; stored in `fixture.Object.Protected["canary"]`.

- [ ] **Step 1: Write failing tests** against an `httptest` toy server: `TestBuildFixtureCreatesObjectPerAccount`, `TestBuildFixtureEmbedsCanaryInFreeTextField`, `TestBuildFixtureWithoutFreeTextMarksStructuralOnly` (fixture object has empty `Protected["canary"]` and `Public["confidence"]="structural"`), `TestBuildFixtureReturnsCreatedForCleanup`, `TestBuildFixtureRefusesUnclassifiedSetupOp`.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement `BuildFixture`. Tokens come from a `runner.SecretResolver`-style lookup passed by `Doer` wrapper; never log them.
- [ ] **Step 4:** Run tests; expect PASS.
- [ ] **Step 5:** Commit `feat(aleef): setup plan, ownership discovery, canary fixture`; push.

---

### Task 6: Property library

**Files:** Create `internal/aleef/property/property.go`, `own.go`, `role.go`, `flow.go`, `idem.go` and a `_test.go` for each.

**Interfaces:**
- Produces:
  - `type Property interface { ID() string; Class() string; Applies(op model.Operation, m model.Model) bool; Templates(ctx TemplateCtx) []Template }`
  - `type Template struct { Property, Description string; Steps []contract.Step; Preconditions contract.Preconditions; MaxAccepted int; DeniedStatuses []int; ForbiddenValues []string; Params map[string]string; SideEffect string }`
  - `type TemplateCtx struct { Op model.Operation; Model model.Model; Fixture fixture.Fixture; Identities []model.Account }`
  - `func All() []Property` returning P-OWN-1/2/3, P-ROLE-1/2, P-AUTH-1/2, P-MC-1, P-IDEM-1/2, P-STATE-1/2, P-RACE-1 exactly as spec section 5.3.
- Properties are general. No property may mention bank resources by name.

- [ ] **Step 1: Write failing tests per file**, each using a tiny in-package toy HTTP server that contains one deliberate flaw of that class (written by the implementer, not the benchmark): `TestOwnTemplatesDetectToyBOLA`, `TestOwnTemplatesCoverBodyQueryHeaderIDs`, `TestRoleTemplatesDetectToyBFLA`, `TestVersionDifferentialDetectsToyLegacyRoute`, `TestFlowTemplatesDetectToyPostApprovalTamper`, `TestIdemTemplatesDetectToyDoubleProcess`, `TestMakerCheckerDetectsToySelfApproval`. Each also asserts the property passes (no finding) against a corrected toy.
- [ ] **Step 2:** Add `TestNoPropertyNamesBankResources` which fails if any property source contains the strings `beneficiary`, `kyc`, `settle`, `ledger`.
- [ ] **Step 3:** Run; expect FAIL.
- [ ] **Step 4:** Implement the properties. Multi-step flows use `co_actor` setup steps; only the final step is graded. Soft-failure rule: a 2xx response whose JSON body has an `error` key, `status:"error"` or `success:false` is treated as denied (documented in `property.go`).
- [ ] **Step 5:** Run `go test ./internal/aleef/property/`; expect PASS.
- [ ] **Step 6:** Commit `feat(aleef): security property library`; push.

---

### Task 7: Deterministic generator and novelty check

**Files:** Create `internal/aleef/generate/generate.go`, `vary.go`, `generate_test.go`; `internal/aleef/novelty/novelty.go`, `novelty_test.go`.

**Interfaces:**
- Consumes: `property.All()`, `model.Model`, `fixture.Fixture`.
- Produces:
  - `type Test struct { ID string; Scenario contract.Scenario; Property string; Params map[string]string; Covered bool }`
  - `type Options struct { Seed int64; MaxTests int; Variations []string }`
  - `func Generate(m model.Model, fx fixture.Fixture, accts []model.Account, opt Options) ([]Test, error)`
  - `novelty.Covered(s contract.Scenario, cat []contract.Scenario) bool` comparing property class and normalized (method, path shape).
- Test ids: `ALEEF-GEN-<property>-<hash8>` of (property, op, params).

- [ ] **Step 1: Write failing tests:** `TestGenerateIsDeterministic` (same input and seed, byte-identical output; different seed changes ordering of variations only), `TestGenerateRespectsMaxTests`, `TestGenerateOutputsPassContractValidate`, `TestGenerateSkipsUnclassifiedAndMoneyMovementOps`, `TestNoveltyMarksCatalogueOverlap`, `TestNoveltyIgnoresIDAndName`.
- [ ] **Step 2:** Run; expect FAIL. If `contract.Validate()` rejects `ALEEF-` ids or categories, record the exact rejection in the QA log and make the smallest additive change in `contract` (allow the `ALEEF` prefix and category `ALEEF`); add a contract test for it.
- [ ] **Step 3:** Implement `Generate` and `Covered`. Variations: identifier source (other account's id, neighbouring id, stale id), field location, method override header, API version, request order, boundary values (0, -1, max, rounding), repeat and parallel counts.
- [ ] **Step 4:** Run tests, including the isolation test; expect PASS.
- [ ] **Step 5:** Commit `feat(aleef): deterministic test generator and novelty check`; push.

---

### Task 8: Runner adapter, state reader and compensating cleanup

**Files:** Create `internal/aleef/exec/exec.go`, `state.go`, `cleanup.go`, `exec_test.go`.

**Interfaces:**
- Consumes: `generate.Test`, `runner.Config`, `model.CreatedObject`.
- Produces:
  - `type Executor struct{...}`; `func New(cfg Config) (*Executor, error)` where `Config{BaseURL string; Fixture fixture.Fixture; Secrets runner.SecretResolver; Created []model.CreatedObject; Doer model.Doer; Model model.Model}`
  - `func (e *Executor) Run(ctx context.Context, t generate.Test) (runner.Report, error)`
  - `type UATState struct{...}` implementing `runner.StateReader` by reading through operations the model marks readable, as the owning account.
  - `type CompensatingReset struct{...}` implementing `runner.Resetter` and exposing `Orphans() []model.CreatedObject`.
- Base URL guard: `New` returns error unless host is loopback (replaced in Task 11).

- [ ] **Step 1: Write failing tests** against a toy server: `TestRunExecutesGeneratedScenarioThroughRunner`, `TestUATStateReaderDetectsModification`, `TestCompensatingResetDeletesOnlyTaggedObjects`, `TestResetFailureSurfacesOrphansAndReasonCleanupFailed`, `TestNewRefusesNonLoopbackBaseURL`, `TestSoftFailure200ErrorBodyNotCountedAsAccess`.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement by constructing `runner.New(runner.Config{...})` per run. Do not copy runner logic.
- [ ] **Step 4:** Run tests; expect PASS.
- [ ] **Step 5:** Commit `feat(aleef): runner adapter, UAT state reader, compensating cleanup`; push.

---

### Task 9: Storage

**Files:** Create `internal/aleef/store/schema.go`, `store.go`, `store_test.go`; modify `cmd/server/main.go` near line 314 to call `aleef/store.EnsureSchema`.

**Interfaces:**
- Produces:
  - `func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) error` creating `aleef_engagements`, `aleef_runs`, `aleef_tests`, `aleef_results`, `aleef_findings`, `aleef_finding_history`.
  - `type Store struct{...}`; `func New(pool *pgxpool.Pool) *Store`
  - `(*Store) SaveResult(ctx, runID string, t generate.Test, rep runner.Report) error`
  - `(*Store) SetFindingState(ctx, id, state, reason, actor string) error` appends to history, never updates in place.
  - Finding states: `candidate`, `verified`, `rejected`, `unconfirmed`. `prior_knowledge` defaults `not_checked`.
  - DB constraint: only role `verifier` writes `verified` (enforced in `SetFindingState` via an explicit `verifiedBy` argument and a check constraint on a non-null `evidence_hash`).

- [ ] **Step 1: Write failing tests** using `internal/testutil` test DB: `TestEnsureSchemaIdempotent`, `TestFindingStateChangeAppendsHistory`, `TestVerifiedRequiresEvidenceHash`, `TestCandidateCannotBeWrittenAsVerifiedWithoutHash`.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement following `apibas_schema.go` conventions (`CREATE TABLE IF NOT EXISTS`, jsonb for reports).
- [ ] **Step 4:** Run tests; expect PASS. Run `go build ./cmd/server`.
- [ ] **Step 5:** Commit `feat(aleef): candidate/finding/run storage`; push.

---

### Task 10: Verifier

**Files:** Create `internal/aleef/verify/verify.go`, `verify_test.go`.

**Interfaces:**
- Consumes: `exec.Executor`, `store.Store`, `generate.Test`.
- Produces:
  - `type Verdict struct { State string; Reproductions int; OwnerControl, NegativeControl bool; EvidenceHash string; Reason string }`
  - `func (v *Verifier) Verify(ctx context.Context, t generate.Test) (Verdict, error)`: runs the test `N` (default 3) times, each preceded by fresh fixture build; runs the owner control and the negative control derived from the same template; promotes to `verified` only when all pass; returns `rejected` or `unconfirmed` otherwise.
  - Evidence hash: SHA-256 of canonical JSON of the sanitized exchanges, state diffs, property id and reproduction steps.

- [ ] **Step 1: Write failing tests** with a toy server that has a stable flaw, a flaky flaw (fails 1 in 2), a broken-oracle server (flags everything) and a legitimately-allowed access: `TestStableFlawBecomesVerified`, `TestFlakyFlawIsNotVerified`, `TestIndiscriminateOracleRejectedByNegativeControl`, `TestOwnerControlFailureRejects`, `TestLegitimateAccessIsUnconfirmedNotVerified`, `TestCleanupFailureBlocksVerification`, `TestCircuitBreakerHaltBlocksVerification`.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement. The verifier is the only code path calling `SetFindingState(... "verified" ...)`; add a test that greps the repo's `aleef` packages for that call outside `verify`.
- [ ] **Step 4:** Run tests, including isolation; expect PASS.
- [ ] **Step 5:** Commit `feat(aleef): verifier with controls and reproduction rule`; push.

---

### Task 11: Safety controls (engagement, classes, limits, breaker, stop)

**Files:** Create `internal/aleef/safety/engagement.go`, `class.go`, `limiter.go`, `breaker.go`, tests; modify `exec/exec.go` (replace the loopback-only guard).

**Interfaces:**
- Produces:
  - `type Class string` with `ClassRead, ClassSetupSafe, ClassReversible, ClassMoney, ClassNotifying, ClassUnknown`.
  - `type Engagement struct { ID, Customer, Environment string; Hosts []string; Approver string; NotBefore, NotAfter time.Time; Accounts, Operations []string; MaxRequests, MaxConcurrent int; RPS float64; SimulatedRail bool; SimulatorBeneficiaries, TestRecipients []string }`
  - `func (e Engagement) Authorize(host string, scope *targetscope.TargetScopeImport, now time.Time) error`: refuses `Environment == "production"`, outside window, host not in `Hosts` (exact origin) or not `targetscope.IsAuthorized`.
  - `func Allow(c Class, e Engagement) error` per spec 5.6 item 2.
  - `type Limiter`, `type Breaker` (halts on 429, three consecutive 5xx, or latency over threshold), `Stop(ctx)` kill switch checked between requests.

- [ ] **Step 1: Write failing tests:** `TestAuthorizeRefusesProduction`, `TestAuthorizeRefusesExpiredWindow`, `TestAuthorizeRefusesUnlistedHost`, `TestMoneyMovementRefusedWithoutSimulatedRail`, `TestUnknownClassNeverRuns`, `TestNotifyingOnlyToListedRecipients`, `TestLimiterCapsConcurrency`, `TestBreakerHaltsOn429`, `TestStopCancelsBetweenRequests`, `TestBudgetExhaustionEndsRun`.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement; wire `Authorize`, `Allow`, `Limiter` and `Breaker` into `exec.Executor`; remove the loopback-only guard and update its test to assert refusal without a valid engagement.
- [ ] **Step 4:** Run `go test ./internal/aleef/...`; expect PASS.
- [ ] **Step 5:** Commit `feat(aleef): engagement authorization and UAT safety controls`; push.

---

### Task 12: Regression export

**Files:** Create `internal/aleef/export/export.go`, `export_test.go`.

**Interfaces:** `func ToRegression(f store.Finding, t generate.Test) (contract.Scenario, []byte, error)` returning the scenario and its YAML, id `ALEEF-REG-<seq>`, with a negative test entry and cleanup list.

- [ ] **Step 1: Write failing tests:** `TestExportedScenarioValidates`, `TestExportedScenarioFailsOnVulnerableToyAndPassesOnFixedToy`, `TestExportIncludesNegativeTest`.
- [ ] **Step 2:** Run; expect FAIL. **Step 3:** Implement. **Step 4:** Run; expect PASS.
- [ ] **Step 5:** Commit `feat(aleef): regression scenario export`; push.

---

### Task 13: API, permission, separate licence gate, console tab

**Files:** Create `internal/api/aleef_handlers.go`, `_test.go`; modify `internal/auth/permissions.go`, `internal/license/tier.go`, `internal/api/product_gate.go`, `internal/api/routes.go`, `internal/api/rbac_matrix_test.go`; add the console tab following the Kubernetes Scenarios tab (commit `6eb47b6c`) layout under `web/`.

**Interfaces:**
- Permissions `CanViewAleef = "aleef:view"`, `CanRunAleef = "aleef:run"`.
- `license.ProductAleef ProductLine = "aleef"`: not present in any `tierProductLines` entry; granted only by an explicit add-on field in the licence. Read `internal/license` first to find where add-ons or flags live; if none exists, add the narrowest one and a test.
- Routes: `POST /api/aleef/engagements`, `POST /api/aleef/runs`, `GET /api/aleef/runs/{id}`, `GET /api/aleef/findings`, `POST /api/aleef/runs/{id}/stop`. `productPrefixes["/api/aleef"] = license.ProductAleef`.

- [ ] **Step 1: Write failing tests:** `TestNoTierIncludesAleef` (iterates `tierProductLines`), `TestAleefRoutesRefusedWithoutAddOn`, `TestAleefRoutesRequirePermission`, `TestRunRefusedWithoutValidEngagement`, `TestFindingsListSeparatesCandidatesFromVerified`, plus the RBAC matrix rows.
- [ ] **Step 2:** Run `go test ./internal/api/ ./internal/license/ ./internal/auth/ -run Aleef -p 1`; expect FAIL.
- [ ] **Step 3:** Implement handlers and wiring. The findings response has two arrays, `candidates` and `verified`, never merged.
- [ ] **Step 4:** Add the console tab with two separated tables (candidates, verified) and a stop button. Verify in a browser per repo convention.
- [ ] **Step 5:** Run the narrow tests, then the full `internal/api` suite with `-p 1`; expect PASS.
- [ ] **Step 6:** Commit `feat(aleef): API, permissions, separate licence gate, console tab`; push.

---

### Task 14: Held-out evaluation harness and QA log

**Files:** Create `internal/aleef/bench/bench.go`, `labels.go`, `bench_test.go`, `cmd/aleef-bench/main.go`.

**Interfaces:**
- Produces:
  - `func Evaluate(ctx context.Context, labels []Label, run func(build string) ([]store.Finding, error)) (Report, error)`
  - `type Report struct { PerFlaw []FlawResult; FixedBuildVerified int; TestsGenerated, TestsRun int; CoveragePerOperation map[string]int; Recall float64 }`
  - `labels.json` loaded from a path given by flag `-labels`, never embedded and never in the repo.
- The command builds the bank twice: fixed, and vulnerable with `-tags aleefsealed` using the owner's `sealed_defects.go`; runs the full pipeline with only the OpenAPI document and accounts as input; scores afterwards.

- [ ] **Step 1: Write failing tests** with synthetic labels and a stub `run`: `TestEvaluateReportsPerFlawResults`, `TestEvaluateFailsMilestoneOnAnyFixedBuildVerifiedFinding`, `TestEvaluatePassRequiresSixOfEightAndAllControls`, `TestEvaluateReportsExactCoverageNotJustRecall`.
- [ ] **Step 2:** Run; expect FAIL. **Step 3:** Implement. **Step 4:** Run; expect PASS.
- [ ] **Step 5:** Rehearse the full pipeline on the fixed build only (no sealed file needed): confirm 0 verified findings, record the numbers.
- [ ] **Step 6:** Owner supplies `sealed_defects.go` and `labels.json` locally. Run `go run -tags aleefsealed ./cmd/aleef-bench -labels <path>`; record per-flaw results in `docs/aleef-mastery-qa-log.md`, including: what the implementer had seen, any property added after seeing results (marked post-hoc), the lab-only limitation, and the sentence that no real-bank readiness is claimed.
- [ ] **Step 7:** Cross-compile for Windows and run a fresh-clone build per repo convention. Commit `docs(aleef): Milestone 1 evaluation results`; push.

---

## Self-review notes

- Spec coverage: model (4,5), properties (6), generation and novelty (7), runner reuse (8), storage and candidate/verified separation (9,10), safety (11), regression (12), API/licence/console (13), benchmark and pass criteria (1,2,14), isolation (3).
- Type consistency: `model.Doer`, `model.CreatedObject`, `generate.Test`, `store.Finding`, `safety.Class` are defined once and consumed by name. `model.OpClass` is a local alias converted to `safety.Class` in the executor to avoid a cycle.
- Known uncertainty: whether `contract.Validate()` accepts `ALEEF-` ids; Task 7 Step 2 resolves it with a minimal additive change. The licence add-on mechanism is unread; Task 13 reads it first.
- Deliberate deviation from spec section 6 order, per owner decision 5: benchmark first; safety controls after the generator, with the loopback-only guard covering the gap.
