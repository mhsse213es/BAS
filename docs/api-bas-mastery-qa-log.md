# API BAS Mastery — QA Log

Blueprint: `docs/api-bas-blueprint.md`. Audit: `docs/api-bas-audit.md`. Branch: `feature/api-bas-phase1`.

## Phase 1 — core engine and vertical slice

Date: 2026-10-20. Scope: contract loader, fixture model, lab (vulnerable and fixed variants), dedicated runner, three-axis grading, one scenario (`API-BAS-AUTHZ-001`, BOLA).

### What was built

| Path | Role |
|---|---|
| `orchestrator/internal/apibas/fixture/fixture.go` | Deterministic synthetic data shared by lab and runner. Two fixtures: `orders-two-tenant`, `orders-no-protected` |
| `orchestrator/internal/apibas/lab/lab.go` | Owned API target. Same contract in `vulnerable` and `fixed` modes. Admin state endpoint, run-tagged cleanup, append-only audit log, planted-flaw registry |
| `orchestrator/internal/apibas/contract/contract.go` | Scenario contract with strict load-time validation |
| `orchestrator/internal/apibas/catalog/API-BAS-AUTHZ-001.yaml` + `catalog.go` | The one Phase 1 scenario, embedded in the binary |
| `orchestrator/internal/apibas/grade/grade.go` | Pure grading rules, three axes, PASS / FAIL / ERROR / SKIPPED |
| `orchestrator/internal/apibas/runner/runner.go` | Preflight, baseline and attack execution, state diff, redacted evidence |
| `orchestrator/internal/apibas/runner/labadmin.go` | State adapter and run-tagged cleanup over the lab admin API |
| `orchestrator/internal/apibas/runner/secrets.go` | In-memory secret resolver (tests and local lab only) |
| `orchestrator/cmd/apibas-lab/main.go` | Starts one lab variant. Credentials from environment only |
| `orchestrator/cmd/apibas-runner/main.go` | CLI runner. Refuses non-loopback targets unless allowlisted with `-allow` |
| `orchestrator/internal/apibas/runner/acceptance_test.go` | Acceptance tests A1–A7, plus credential, evidence and flaw-traceability tests |
| `orchestrator/internal/apibas/grade/grade_test.go` | Table-driven tests for every grading rule |

Nothing under `scenarios/` was changed. No `.sig` file was touched. No existing package was modified.

### Acceptance tests (blueprint section 10, Phase 1)

Run with `go test ./internal/apibas/... -count=1` from `orchestrator/`. Each test drives the real lab over HTTP.

| ID | Requirement | Test | Result |
|---|---|---|---|
| A1 | Vulnerable build: planted BOLA detected, FAIL, exploited, disclosure shown | `TestA1_VulnerableBuild_BOLA_Fails` | PASS |
| A2 | Fixed build: same scenario PASSes with control enforced and ground truth present | `TestA2_FixedBuild_PassesWithEvidence` | PASS |
| A3 | Lab down is ERROR, never PASS or SKIP | `TestA3_TargetDown_IsError` | PASS |
| A4 | Adapter removed: SKIPPED `ADAPTER_UNAVAILABLE`, zero API requests sent | `TestA4_NoStateAdapter_SkipsWithoutTraffic` | PASS |
| A5 | Attacker identical to owner: SKIPPED `NOT_CROSS_IDENTITY`, zero attack traffic | `TestA5_SameIdentity_NoFinding` | PASS |
| A6 | Cleanup removes only run-tagged records; seed data and audit log survive | `TestA6_CleanupTouchesOnlyTaggedRecords` | PASS |
| A7 | 2xx with no disclosure is inconclusive, never FAIL | `TestA7_2xxWithoutDisclosure_IsInconclusive` | PASS |

Additional tests, all passing:
- `TestMissingCredential_IsPreconditionSkip`: an unresolvable credential is a precondition skip, and no request is sent.
- `TestEvidenceNeverContainsCredentials`: no bearer token appears in any evidence field.
- `TestFlawRegistryLinksToCatalog`: every planted flaw names a scenario that exists in the catalog.
- `TestAssess_Rules` (9 cases) and `TestAssess_InconclusiveNeverPassesOrFails`: the grading table.

Test output summary: `grade` ok, `runner` ok, all 12 top-level tests pass (10 in `runner`, 2 in `grade`; the grade table expands to 9 subtests). The `catalog`, `contract`, `fixture` and `lab` packages have no test files of their own; they are exercised through the runner tests.

### End-to-end CLI smoke test

Lab and runner were run as separate processes on loopback. Tokens were random per run and provided via environment variables.

| Lab mode | Runner result | Axes | Attack response |
|---|---|---|---|
| vulnerable | FAIL | exploit: exploited, control: failed, evidence-backed | `GET /api/orders/ORD-2001` → 200 |
| fixed | PASS | exploit: not_exploited, control: enforced, evidence-backed | `GET /api/orders/ORD-2001` → 403 |

The lab and runner logs were grepped for all three generated tokens: zero matches.

### Bugs found and fixed during Phase 1

1. **A downed lab was reported as SKIPPED.** The state snapshot failed before traffic and the runner returned a skip. Fixed: state-read failures are now ERROR, with `TARGET_UNREACHABLE` when the target is down. Covered by A3.
2. **Owner's own response was stored unredacted.** Evidence for the baseline step held raw protected values. Fixed: the baseline is also redacted. Covered by A1's evidence check across every exchange.
3. **YAML field value with a colon** (`BFSI: ...`) would have parsed as a nested mapping. Fixed by quoting.
4. **Constant name collision** in the first draft of `grade` (`Inconclusive` in two axes). Rewritten with distinct names before any test ran.

### Decisions taken in Phase 1 (recorded for review)

- **Scenario file location.** Moved from `scenarios/api-bas/` (blueprint D4) to an embedded catalog. Reason: the live engine walks `scenarios/` recursively and would load these as live scenarios. This was confirmed in `orchestrator/internal/scenario/engine.go`.
- **Lab location.** `orchestrator/internal/apibas/lab`, started by `cmd/apibas-lab`, instead of a top-level `tools/apibas-lab/`. Reason: Go's `internal` rule means the acceptance tests can only import it from inside the orchestrator module. It is not mounted by `cmd/server`.
- **Inconclusive is SKIPPED, not ERROR.** The outcome layer has no separate "inconclusive" result. A run that cannot prove either outcome is SKIPPED with reason `EVIDENCE_INCONCLUSIVE`. It is never PASS or FAIL.
- **Detection is `not_evaluated`** on every outcome. The scenario declares this explicitly, so no detection claim can be inferred.
- **Runner is a CLI, not yet scheduled.** Per your decision D2, the orchestrator will schedule it. Scheduling is not part of Phase 1.

### Limitations and open items (not hidden)

- **Only one flaw and one scenario.** The lab plants `LAB-AUTHZ-BOLA-001` only. Phase 1 proves the mechanism, not coverage.
- **No financial or healthcare workflows yet.** Your direction requires them. They come with Phase 3 (business logic) and Phase 5 (sector packs).
- **crAPI not integrated.** It is a benchmark for scenario design, as you specified. No crAPI scenario has been run or compared.
- **Credentials come from environment variables** in the CLI and from an in-memory map in tests. The production secret store behind `runner.SecretResolver` is not built.
- **No orchestrator scheduling, no policy enforcement, no result persistence.** These belong to the orchestrator side of D2 and are not built.
- **Evidence is in-memory only.** Nothing is written to the orchestrator database. No persistence layer exists yet.
- **Race detector not run.** `go test -race` needs cgo, which is not enabled on this Windows host.
- **Not run against a staging or customer target.** Only loopback smoke tests were run.
- **Regulatory sourcing (D6) not started.** It runs in parallel and is not a Phase 1 dependency.
- **Repository-wide build not verified.** Only the new packages were built and tested. The main checkout has uncommitted changes from other sessions, which were not touched.

### Verification commands

```
cd orchestrator
gofmt -l internal/apibas cmd/apibas-lab cmd/apibas-runner   # no output
go vet ./internal/apibas/... ./cmd/apibas-lab ./cmd/apibas-runner   # clean
go test ./internal/apibas/... -count=1                       # ok: grade, runner
```

### Status

Phase 1 acceptance tests A1–A7 pass against the real lab. Phase 1 is merged to `main` (`0226f2e3`). Phase 2 has started; see the next section for what is and is not done.

## Phase 2 — first tranche (core security vectors)

Date: 2026-10-20. Branch: `feature/api-bas-phase2`. Phase 2 as a whole (blueprint section 10) covers about 50 sub-techniques. This tranche covers five scenarios, which is a small share of it. The rest is open.

### Scenarios in this tranche

| ID | Sub-technique | Claim type | Vulnerable build | Fixed build | Side effect |
|---|---|---|---|---|---|
| API-BAS-AUTHZ-001 | AUTHZ BOLA (Phase 1) | cross_identity | FAIL, exploited | PASS | READ_ONLY |
| API-BAS-AUTHN-001 | Missing authentication on protected endpoint | authentication | FAIL, exploited | PASS (401) | READ_ONLY |
| API-BAS-AUTHN-002 | Revoked token accepted | authentication | FAIL, exploited | PASS (401) | READ_ONLY |
| API-BAS-AUTHZ-002 | BFLA: customer invokes admin status change | function_level | FAIL, exploited (state change) | PASS (403) | STATE_CHANGE_SANDBOX |
| API-BAS-AUTHZ-003 | Property-level mass assignment of owner_id | property_level | FAIL, exploited (state change) | PASS (403) | STATE_CHANGE_SANDBOX |

Flaws in the lab: `LAB-AUTHN-ANON-001`, `LAB-AUTHN-REVOKE-001`, `LAB-AUTHZ-BFLA-001`, `LAB-AUTHZ-MASS-001`, plus Phase 1's `LAB-AUTHZ-BOLA-001`. Each is registered against its scenario, and `TestFlawRegistryLinksToCatalog` checks the link.

### What changed in the framework

- **Claim types** (`contract`): each scenario declares what it depends on: `cross_identity`, `property_level`, `authentication` or `function_level`. The cross-identity preflight now applies only to cross-identity claims. A property-level claim requires the attacker to own the object. Other claims do not depend on ownership.
- **Per-scenario denial codes** (`denied_statuses`, `grade`): enforcement is a list the scenario declares, not a fixed set. A 400 counts as a block only where a scenario says so.
- **Auth modes per step** (`valid`, `none`, `revoked`): an anonymous step carries no credential and must use identity `anonymous`.
- **Request bodies** for PATCH steps.
- **State diff between baseline and attack**, not from before the baseline. A baseline write is never blamed on the attacker.
- **Side-effect classes tied to content**: a READ_ONLY scenario that contains a mutating step fails to load. A sandbox scenario must mutate and must declare cleanup.
- **Sandbox cleanup**: sandbox scenarios require a reset adapter. They are reset before and after the run. If the reset after the run fails, the outcome is ERROR (`CLEANUP_FAILED`), never PASS.
- **Lab**: revocation list, anonymous serving in vulnerable mode only, PATCH with field binding, admin status route, and `POST /lab/reset`. Both modes use the same routes and the same contract.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass; 18 top-level tests in `runner` and 2 in `grade`, zero failures.

New in this tranche:
- `TestPhase2_VulnerableFailsFixedPasses`: each of the four new scenarios, vulnerable FAIL and fixed PASS (eight subtests).
- `TestPhase2_SandboxRunIsResetAfterwards`: after a BFLA run against the vulnerable build, the seed status is restored and the report records `Reset: ok`.
- `TestPhase2_SandboxWithoutResetIsSkippedWithoutTraffic`: a sandbox scenario with no reset adapter does not run and sends no requests.
- `TestPhase2_PropertyClaimRequiresOwnerAttacker`: a property-level scenario with a non-owner attacker is a precondition skip with no traffic.
- `TestPhase2_MissingRevokedCredentialIsPreconditionSkip`: without the revoked credential, AUTHN-002 is a precondition skip, not a pass.
- `TestPhase2_RevokedAttackIsRefusedByFixedBuild`: the attack request really carries the revoked credential, and the fixed build refuses it with 401.
- `TestPhase2_AnonymousAttackSendsNoCredential`: the anonymous attack sends no Authorization header.
- `TestPhase2_MassAssignmentChangesOwnerOnlyInVulnerable`: the vulnerable PATCH really changes the owner in state. The PATCH echoes protected values, so a FAIL could otherwise come from disclosure alone.

### CLI smoke test (both lab modes, all five scenarios)

Lab and runner ran as separate processes on loopback. Result from each run:

| Scenario | vulnerable | fixed |
|---|---|---|
| API-BAS-AUTHZ-001 | FAIL, exploited | PASS |
| API-BAS-AUTHN-001 | FAIL, exploited | PASS |
| API-BAS-AUTHN-002 | FAIL, exploited | PASS |
| API-BAS-AUTHZ-002 | FAIL, exploited, reset ok | PASS, reset ok |
| API-BAS-AUTHZ-003 | FAIL, exploited, reset ok | PASS, reset ok |

The lab log was grepped for all four generated tokens: zero matches.

The smoke test found one defect, now fixed: the runner CLI did not pass the reset adapter, so sandbox scenarios were SKIPPED with `ADAPTER_UNAVAILABLE` rather than run. The fail-closed behaviour was correct; the wiring was not.

### Configuration hazard (recorded, not yet guarded)

If the lab is started without the revoked token, its vulnerable build refuses that token as invalid, returns 401, and AUTHN-002 would report PASS for the wrong reason. The CLI lab and runner both read `APIBAS_CUSTOMER_A_REVOKED_TOKEN`, so the two sides stay in step. Nothing enforces this yet. A future guard should have the runner confirm the revoked token is known to the lab before grading.

### Not in this tranche (open)

- Injection (INJ), gateway and perimeter (GWAY), data exposure (DATA), abuse and rate limits (ABUSE), integrations and webhooks (INTEG), discovery (DISC) are not started.
- Remaining AUTHN sub-techniques (expired and malformed tokens, JWT algorithm and claims, API keys, session binding) and remaining AUTHZ sub-techniques (vertical and horizontal escalation beyond the two above, cross-tenant, parent-child, bulk, method and version bypass, cache leakage, async export).
- No negative fixture for AUTHZ-002 or AUTHZ-003 beyond the fixed build. Blueprint section 9 requires one per scenario, so this is open.
- The orchestrator still does not schedule runs or persist results. The production secret store is still not built.
- crAPI benchmark comparison not run.

## Phase 2b — second tranche

Branch: `feature/api-bas-phase2b` (from `main` after the Phase 2 merge). Three more scenarios, bringing the total to eight.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-AUTHZ-010 | Authorization bypass through an alternate API version | cross_identity | FAIL, exploited | PASS (403) | READ_ONLY |
| API-BAS-DISC-003 | Debug/diagnostic endpoint exposed to customers | function_level | FAIL, exploited | PASS (404, route not mounted) | READ_ONLY |
| API-BAS-DATA-001 | Hidden protected fields in a summary projection | property_level, clean_is_enforcement | FAIL, exposed | PASS (200, public fields only) | READ_ONLY |

New flaws: `LAB-AUTHZ-VERSION-001`, `LAB-DISC-DEBUG-001`, `LAB-DATA-PROJ-001`.

### Framework change

- **`clean_is_enforcement`** (contract, grade, runner): a 2xx with no leak and no state change is PASS only where a scenario declares it. Without the declaration the same evidence stays inconclusive, as before. The leak and state-change FAIL rules still take precedence. The contract refuses the declaration unless the response adapter is in the ground truth, because the response adapter is what proves "no leak".

### Why the projection control is not vacuous

A 200 with no leak could also come from a route that returns nothing. `TestPhase2b_FixedSummaryIsServedAndClean` checks that the fixed summary returns a non-empty body with no protected values, so the PASS reflects a served projection.

`TestPhase2b_DebugRouteAbsentFromFixedBuild` checks that the fixed build refuses the debug route by not mounting it (404), so there is no check left to bypass.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass, zero failures. New: `TestAssess_CleanIsEnforcement` (grade), `TestCleanIsEnforcementRequiresResponseAdapter` (contract), `TestPhase2b_VulnerableFailsFixedPasses` (six subtests), and the two checks above.

### CLI smoke test (both modes, eight scenarios)

Vulnerable: all eight FAIL, exploited. Fixed: all eight PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Coverage is now eight scenarios from about 50 Phase 2 sub-techniques.
- Not started: injection (INJ), gateway (GWAY), abuse (ABUSE, which needs multi-request steps), integrations (INTEG), and most of AUTHN and AUTHZ.
- The configuration hazard from Phase 2 still stands: nothing enforces that the lab knows the revoked token.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.


## Phase 3 tranche — third tranche

Branch: `feature/api-bas-phase3` (from `main` after the Phase 2b merge). Three more scenarios, bringing the total to eleven.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-AUTHN-003 | Unsigned JWT (alg none) accepted | authentication, forged subject | FAIL, exploited | PASS (401) | READ_ONLY |
| API-BAS-DATA-004 | Unbounded collection returns other customers' records | cross_identity, clean_is_enforcement | FAIL, exposed | PASS (200, own projection, capped) | READ_ONLY |
| API-BAS-GWAY-003 | HTTP method override bypasses method policy | function_level | FAIL, state changed | PASS (405) | STATE_CHANGE_SANDBOX |

New flaws: `LAB-AUTHN-ALG-001`, `LAB-DATA-LIST-001`, `LAB-GWAY-OVERRIDE-001`.

### Framework additions

- **Forged tokens** (`auth: alg_none`, `forge_as`): the runner builds an unsigned JWT for the named identity and sends it only to the lab. The contract refuses `alg_none` without `forge_as`, and refuses `forge_as` with any other auth mode.
- **Per-step headers** (`headers`): used for the method-override header.
- **POST steps**: supported, with a required body.
- **Revocation guard**: before a revoked-token scenario runs, the runner asks the lab, through the admin-only `POST /lab/token-status`, whether the attack credential is known and revoked. If it is not, the run is an ERROR (`LAB_CONFIG_MISMATCH`) with no attack traffic. This closes the hazard recorded in the Phase 2 log, where a lab missing the revoked token would have made AUTHN-002 pass for the wrong reason.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass, zero failures. New in `phase3_test.go`:
- `TestPhase3_VulnerableFailsFixedPasses` (six subtests)
- `TestPhase3_ForgedTokenIsSentAndRefused`: the attack really carries an alg none token, and the fixed build refuses it with 401.
- `TestPhase3_FixedCollectionIsServedAndClean`: the fixed list holds the caller's order and not the other customer's.
- `TestPhase3_FixedBuildIgnoresMethodOverride`: the fixed build answers the POST with 405.
- `TestPhase3_RevokedGuardRefusesMisconfiguredLab`: a lab that knows the token but does not revoke it gives ERROR with zero API traffic.

### CLI smoke test (both modes, all eleven scenarios)

Vulnerable: all eleven FAIL, exploited. Fixed: all eleven PASS, not exploited. Token check against the lab logs: zero matches.

### Build check

- `go list -deps ./cmd/server` contains no `apibas` package, so the lab is not in the orchestrator server binary.
- `go build ./cmd/server` succeeds on this Windows host. The Windows build script compiles only `./cmd/server`, and signs only the repo-root `scenarios/` tree. The embedded API BAS catalog is outside that tree, so it needs no signature.

### Still open

- Eleven scenarios of roughly 50 Phase 2 sub-techniques.
- Not started: injection (INJ), most of gateway (GWAY), abuse (ABUSE, which needs multi-request steps), integrations (INTEG), and most of the remaining AUTHN and AUTHZ items.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.


## Phase 4 tranche — fourth tranche

Branch: `feature/api-bas-phase4` (from `main`, after the build-script fix). Three more scenarios, bringing the total to fourteen.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-DISC-002 | Retired API version still serves records without credentials | authentication | FAIL, exploited | PASS (404, route not mounted) | READ_ONLY |
| API-BAS-INTEG-003 | Webhook test endpoint fetches internal addresses (SSRF) | function_level | FAIL, exploited | PASS (403, refused before fetch) | STATE_CHANGE_SANDBOX |
| API-BAS-DATA-003 | Malformed-body error discloses another customer's record | cross_identity | FAIL, exploited | PASS (generic 400) | STATE_CHANGE_SANDBOX |

New flaws: `LAB-DISC-DEPRECATED-001`, `LAB-INTEG-SSRF-001`, `LAB-DATA-ERRLEAK-001`.

### Framework addition

- **`{lab_url}` in request bodies**: the runner substitutes the target's base URL, so a body can name an address on the target itself. The SSRF scenario needs this, because the target's address is only known at run time.

### Notes

- The SSRF target is the lab's own `/internal/orders/{id}` route, which has no credential check by design. The fixed build refuses loopback, private and unresolvable destinations before fetching. The fixed build refuses any hostname that is not an IP literal, which is conservative: it fails closed.
- `TestPhase4_SSRFTargetsInternalRecord` checks that the vulnerable build really returns the internal record, so the FAIL is not from an empty response.
- `TestPhase4_FixedSSRFRefusedBeforeFetch` checks the fixed build returns 403 with no record in the body.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass, zero failures. New in `phase4_test.go`: `TestPhase4_VulnerableFailsFixedPasses` (six subtests), `TestPhase4_SSRFTargetsInternalRecord`, `TestPhase4_FixedSSRFRefusedBeforeFetch`, `TestPhase4_RetiredRouteAbsentFromFixedBuild`, `TestPhase4_FixedErrorIsGeneric`.

### CLI smoke test (both modes, all fourteen scenarios)

Vulnerable: all fourteen FAIL, exploited. Fixed: all fourteen PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Fourteen scenarios of roughly 50 Phase 2 sub-techniques.
- Not started: injection (INJ), most of gateway (GWAY), abuse (ABUSE, which needs multi-request steps), most of integrations and discovery, and most of the remaining AUTHN and AUTHZ items.
- Campaigns with more than two steps are not supported yet, so chained attacks such as vertical escalation (use a planted role change, then the admin route) cannot be expressed.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on this tranche. The garble step was verified from a short path on the earlier commit. You said you will build it later.


## Phase 5 tranche — fifth tranche

Branch: `feature/api-bas-phase5` (from `main`). Two more scenarios, bringing the total to sixteen.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-AUTHN-008 | Session binding and identity confusion (caller header overrides token identity) | cross_identity | FAIL, exploited | PASS (403) | READ_ONLY |
| API-BAS-AUTHZ-007 | Bulk operation authorization (mixed-ownership batch) | cross_identity | FAIL, state changed | PASS (403, whole batch refused) | STATE_CHANGE_SANDBOX |

New flaws: `LAB-AUTHN-SESSION-001`, `LAB-AUTHZ-BULK-001`.

### Notes

- `LAB-AUTHN-SESSION-001` applies to every vulnerable route, but only when the request carries `X-Customer-Id`. Other scenarios never send that header, so they are unaffected.
- The bulk fixed build refuses the whole batch when any listed order is not the caller's, including the caller's own order. The scenario's check is on the whole batch, not on individual orders.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New in `phase5_test.go`: `TestPhase5_VulnerableFailsFixedPasses` (four subtests), `TestPhase5_IdentityHeaderIsHonouredOnlyWhenVulnerable`, `TestPhase5_FixedBulkRefusesWholeBatch`.

### CLI smoke test (both modes, all sixteen scenarios)

Vulnerable: all sixteen FAIL, exploited. Fixed: all sixteen PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Sixteen scenarios of roughly 50 Phase 2 sub-techniques.
- Multi-step campaigns are not supported, so chained attacks such as vertical escalation cannot be expressed yet.
- Not started: injection (INJ), most of gateway (GWAY), abuse (ABUSE, which needs multi-request steps), most of integrations and discovery, and most of the remaining AUTHN and AUTHZ items.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on this tranche. You said you will build it later.


## Phase 6 tranche — sixth tranche (multi-step chains)

Branch: `feature/api-bas-phase6` (from `main`). One scenario, bringing the total to seventeen. This tranche also adds the framework support that vertical escalation needs.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-AUTHZ-004 | Vertical escalation by self-assigning an admin role (three-step chain) | function_level | FAIL, state changed | PASS (chain stops at the refused role change) | STATE_CHANGE_SANDBOX |

New flaw: `LAB-AUTHZ-PRIVESC-001`.

### Framework addition: setup steps

A scenario now has a baseline, zero or more **setup** steps, and a final **attack** step.

- Setup steps must use the attacker's identity with a valid token. The contract refuses anything else. `TestSetupStepMustUseAttackerIdentity` covers this.
- Setup steps run in order. A denial stops the chain, and the denied step becomes the attack result, because the control held there. A 2xx lets the chain continue. Any other status, and any transport failure, also stops the chain, graded as before.
- The state is read between the baseline and the first attack-side step, as before.

### Notes

- The fixed build refuses the role change, so the final admin-route call is never sent. The test `TestPhase6_EscalationFixedStopsAtSetup` checks that exactly two exchanges were sent.
- The vulnerable build runs the whole chain, and `TestPhase6_EscalationFailsOnVulnerablePassesOnFixed` checks all three exchanges, including the final 200.
- The admin-route check for the v2 route applies in both builds. The only planted flaw on this chain is the self-service role change. This keeps the chain's result tied to one flaw.
- Reset clears roles, so a sandbox run cannot leave an escalated role behind for the next run.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass, zero failures.

### CLI smoke test (both modes, all seventeen scenarios)

Vulnerable: all seventeen FAIL, exploited. Fixed: all seventeen PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Seventeen scenarios of roughly 50 Phase 2 sub-techniques.
- Not started: injection (INJ), most of gateway (GWAY), abuse (ABUSE, which needs repeated requests and a count-based grader), most of integrations and discovery, and most of the remaining AUTHN and AUTHZ items.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on this tranche. You said you will build it later.


## Phase 7 tranche — seventh tranche

Branch: `feature/api-bas-phase7` (from `main`). Two more scenarios, bringing the total to nineteen.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-AUTHZ-006 | Parent-child authorization (item of another order via own parent) | cross_identity | FAIL, exposed | PASS (404) | READ_ONLY |
| API-BAS-INTEG-005 | Internal service authentication gap (customer token on internal route) | authentication | FAIL, exposed | PASS (401, no record) | READ_ONLY |

New flaws: `LAB-AUTHZ-PARENT-001`, `LAB-INTEG-INTERNAL-001`.

### Notes

- Fixture objects now carry child items. Each item belongs to exactly one order.
- The fixed internal route requires an internal-service credential (`Config.InternalToken`). When none is configured, the fixed build refuses every internal call. The SSRF scenario is unaffected, because the fixed build refuses its loopback destination before fetching.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New in `phase7_test.go`: `TestPhase7_VulnerableFailsFixedPasses` (four subtests), `TestPhase7_ForeignItemReturnedOnlyWhenVulnerable`, `TestPhase7_FixedInternalRouteRefusesCustomerToken`.

### CLI smoke test (both modes, all nineteen scenarios)

Vulnerable: all nineteen FAIL, exploited. Fixed: all nineteen PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Nineteen scenarios of roughly 50 Phase 2 sub-techniques.
- Still open, and needing framework work: counted-request abuse scenarios (ABUSE), header-level evidence for CORS and caching (DISC-005, DATA-006), a fixture SIEM for detection (Phase 4), and GraphQL, gRPC, SOAP, WebSocket, and async adapters.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on these tranches. You said you will build it later.


## Phase 8 tranche — eighth tranche (single-step batch)

Branch: `feature/api-bas-phase8` (from `main`). Three single-step scenarios, bringing the total to twenty-two.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-AUTHZ-012 | Export job of another customer fetched by ID | cross_identity | FAIL, exposed | PASS (404) | READ_ONLY |
| API-BAS-BIZ-002 | Negative order quantity accepted by the update endpoint | property_level | FAIL, state changed | PASS (400, unchanged) | STATE_CHANGE_SANDBOX |
| API-BAS-INTEG-008 | Integration webhook secret readable by a non-owner | cross_identity | FAIL, exposed | PASS (403, no secret) | READ_ONLY |

New flaws: `LAB-AUTHZ-EXPORT-001`, `LAB-BIZ-QTY-001`, `LAB-INTEG-WHSEC-001`.

### Bug found and fixed in this tranche

The first vulnerable BIZ-002 run was graded SKIPPED / EVIDENCE_INCONCLUSIVE, not FAIL. The state diff was ignoring the quantity field: the runner's `StateRecord` only held ID, owner, status and tag. `sameState` therefore could not see a quantity change, and the grader reported the attack as neither exploiting nor enforcing. The fix adds `Quantity` to `StateRecord` and to the state adapter's decode. This is a framework bug, not a scenario bug. Any future scenario that changes a field outside the four original ones depends on this fix.

### Notes

- The PATCH response for an order now carries public fields only. The old response echoed protected values to the owner, so an owner's own update could count as disclosure, and the FAIL would have been wrong. The state diff is what grades a write.
- The fixed build checks quantity before the ownership check. A non-owner who sends a bad quantity therefore gets 400, not 403. The scenario only sends the owner's request, so the grade is unaffected, but the order of checks is worth knowing.
- The fixture now carries a webhook secret in each order's protected values, which the response adapter redacts.
- Exports are derived from orders: `EXP-<n>` belongs to `ORD-<n>`. There is no separate export store, so reset cannot leave stale exports behind.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New in `phase8_test.go`: `TestPhase8_VulnerableFailsFixedPasses` (six subtests), `TestPhase8_FixedRefusesNegativeQuantity`, `TestPhase8_IntegrationSecretOnlyWhenVulnerable`.

### CLI smoke test (both modes, all twenty-two scenarios)

Vulnerable: all twenty-two FAIL, exploited. Fixed: all twenty-two PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Twenty-two scenarios of roughly 50 Phase 2 sub-techniques.
- Not started, and needing framework work: counted-request abuse scenarios (ABUSE), header evidence for CORS and caching (DISC-005, DATA-006), a fixture SIEM for detection (Phase 4), and GraphQL, gRPC, SOAP, WebSocket and async adapters.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on these tranches. You said you will build it later.


## Phase 9 tranche — response-header evidence

Branch: `feature/api-bas-phase9` (from `main`). This tranche adds framework support for response-header evidence, then one scenario that uses it, bringing the total to twenty-three.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-DISC-005 | Permissive CORS reflects an untrusted origin | authentication | FAIL, exploited (reflected origin) | PASS (403 for untrusted origin) | READ_ONLY |

New flaw: `LAB-DISC-CORS-001`.

### Framework addition: forbidden response headers

- A scenario may declare `forbidden_response_headers`: a list of `{name, value}` pairs. Both are required.
- The runner captures the attack response's headers. Each header whose name and exact value match a rule counts as exposure.
- Any exposure is graded FAIL / exploited, the same way a leaked protected value or a state change is. A clean 2xx passes only when the scenario declares `clean_is_enforcement`. Otherwise the scenario must declare a denial status.
- Headers are not written to the report. Only the grading outcome is recorded, so no header values leave the runner beyond what the report already holds.

### Design notes

- The fixed build refuses requests with an untrusted Origin with 403. The contract requires an explicit denial status, so a 200 clean pass isn't available in this scenario. That is the same design as the other scenarios.
- The vulnerable build reflects any Origin in `Access-Control-Allow-Origin`, which is the usual CORS misconfiguration.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New tests: `grade/headers_test.go` (exposure is exploitation; clean headers pass when enforced) and `runner/phase9_test.go` (vulnerable FAIL, fixed PASS with enforced control).

### CLI smoke test (both modes, all twenty-three scenarios)

Vulnerable: all twenty-three FAIL, exploited. Fixed: all twenty-three PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Twenty-three scenarios of roughly 50 Phase 2 sub-techniques.
- API-BAS-DATA-006 (cache poisoning and private-response caching) is partly unblocked: the header evidence exists now, but it also needs a response-caching model in the lab. It is not written yet.
- Not started, and still needing framework work: counted-request abuse scenarios (ABUSE), a fixture SIEM for detection (Phase 4), and GraphQL, gRPC, SOAP, WebSocket and async adapters.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on these tranches. You said you will build it later.
