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


## Phase 10 tranche — counted attack requests

Branch: `feature/api-bas-phase10` (from `main`). This tranche adds counted-request support, then one scenario that uses it, bringing the total to twenty-four.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-ABUSE-001 | Missing rate limit on failed verification attempts | property_level | FAIL, exploited (five accepted) | PASS (three accepted, then 429) | STATE_CHANGE_SANDBOX |

New flaw: `LAB-ABUSE-OTP-001`.

### Framework addition: counted attack requests

- A step may declare `repeat` (0 to 50). Only the attack step may repeat. A repeat on any other step is refused when the scenario loads.
- A repeated attack declares `max_accepted_attempts`, which must be at least 1 and less than the repeat count. Without a repeat, it is refused.
- An **accepted** attempt is any response that is neither in `denied_statuses` nor a server fault (5xx). Accepted attempts above the maximum grade as FAIL / exploited.
- A server fault stops the repeats early and is graded as ERROR, the same as a single request.
- The leak and forbidden-header checks run over every repeat. A leak in any response counts, not only the last.

### Notes

- The lab's counter is per caller and order. It is not in the state diff: the grade depends on the number of accepted attempts, not on a stored value. Reset clears the counter.
- The vulnerable build accepts every guess. The fixed build accepts three and then answers 429.
- The scenario's claim is property_level, because the owner runs the attempts against their own order.

### Bug found during the tranche

The first run of the framework edit stopped partway through. The script wrote two files and then failed on a third, leaving them half-applied. The files were restored to their committed state and the script rerun in full. All edits are in one step, and the build and tests were rerun from a clean state.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New tests: `grade/counted_test.go` (over-limit is exploitation; within-limit passes), `contract/repeat_test.go` (limit required; repeat only on the attack step; a valid repeat parses), `runner/phase10_test.go` (vulnerable FAIL, fixed PASS; the fixed build's exchange sequence is exactly 200, 401, 401, 401, 429, 429).

### CLI smoke test (both modes, all twenty-four scenarios)

Vulnerable: all twenty-four FAIL, exploited. Fixed: all twenty-four PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Twenty-four scenarios of roughly 50 Phase 2 sub-techniques.
- ABUSE-002 through ABUSE-010 need more than repeat counting: expensive-request timing, pagination and batch sizes, upload bounds, and others each need their own evidence. Not written.
- Not started: a fixture SIEM for detection (Phase 4), protocol adapters for GraphQL, gRPC, SOAP, WebSocket and async, and a response-caching model for DATA-006.
- The orchestrator still does not schedule runs or persist results, and the production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on these tranches. You said you will build it later.


## Phase 11 tranche — response caching (DATA-006)

Branch: `feature/api-bas-phase11` (from `main`). Two framework changes and one scenario, bringing the total to twenty-five.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-DATA-006 | Authenticated response marked publicly cacheable | property_level | FAIL, exploited (public caching directive) | PASS (private, no-store) | READ_ONLY |

New flaw: `LAB-DATA-CACHE-001`.

### Framework changes

- **Header match modes.** A `forbidden_response_headers` rule may set `match: exact` (the default) or `match: contains`. Contains is a case-insensitive substring match, so `public` matches `public, max-age=300`. Any other value is refused when the scenario loads.
- **Clean-pass scenarios without a denial list.** A scenario that sets `clean_is_enforcement` may leave `denied_statuses` empty. Before this change, every scenario had to list a denial status, even one whose enforcement is a clean 2xx.

### Design notes

- The first attempt put the caching header on the order route. The fixed build then failed for a different reason: the owner's own order response includes protected values, and the grader counted that as a leak. The caching check now uses a dedicated owner-only status route, `GET /api/orders/{id}/status`, which returns public fields only in both builds. A FAIL there can only come from the caching header.
- The caching header is set only on the status route, so the other scenarios are unaffected.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New: `runner/phase11_test.go` (vulnerable FAIL, fixed PASS with enforced control).

### CLI smoke test (both modes, all twenty-five scenarios)

Vulnerable: 25 of 25 FAIL, exploited. Fixed: 25 of 25 PASS, not exploited. Token check against the lab logs: zero matches.

Note: the first smoke run in this tranche reported every scenario as a mismatch. The cause was the harness: it matched compact JSON, but the runner prints spaces after colons. The harness was fixed and the whole run repeated. The lab was not changed.

### Still open

- Twenty-five scenarios of roughly 50 Phase 2 sub-techniques.
- ABUSE-002 through ABUSE-010 need evidence not yet in the framework: timing for expensive requests, pagination and batch-size limits, upload and decompression bounds, and others.
- Not started: a fixture SIEM for detection (Phase 4), protocol adapters for GraphQL, gRPC, SOAP, WebSocket and async, and orchestrator scheduling and persistence. The production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on these tranches. You said you will build it later.


## Phase 12 tranche — pagination limits (ABUSE-003)

Branch: `feature/api-bas-phase12` (from `main`). One framework change and one scenario, bringing the total to twenty-six.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-ABUSE-003 | Excessive pagination size | property_level | FAIL, exploited (page of 100000 granted) | PASS (400 for limit above 100) | READ_ONLY |

New flaw: `LAB-ABUSE-PAGE-001`.

### Framework change: granted page size

- A scenario may set `max_granted_page_size`. The grader reads the `page_size` integer from each attack response's JSON body. A page size above the maximum is exploitation.
- A response that is not a JSON object, or has no integer `page_size`, counts as zero. A missing field therefore never causes a FAIL.
- The field must not be negative.
- The response body is kept only for this check. It is not written to the report, and the existing redaction still applies to what the report holds.

### Limitation

The check reads the page size the server reports as granted. It does not count the items the response actually returned. The fixture has two orders, so a page of up to 100 can never contain more items than the fixture holds, and an item count would not test the cap. An item-count check needs a fixture with more records than the cap. That is a fixture change and is recorded as an open item.

### Design notes

- The page route is new (`GET /api/orders/page`). The existing list route returns a plain array, and other scenarios depend on that shape.
- The vulnerable build grants the requested size and reports it. The fixed build refuses sizes above 100 before doing any work.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New: `runner/phase12_test.go` (vulnerable FAIL, fixed PASS, fixed attack status 400).

### CLI smoke test (both modes, all twenty-six scenarios)

Vulnerable: 26 of 26 FAIL, exploited. Fixed: 26 of 26 PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Twenty-six scenarios of roughly 50 Phase 2 sub-techniques.
- Item-count pagination evidence needs a fixture with more records than the cap (see Limitation).
- ABUSE-002, ABUSE-004 to ABUSE-010: timing for expensive requests, upload and decompression bounds, and others. Not written.
- Not started: a fixture SIEM for detection (Phase 4), protocol adapters for GraphQL, gRPC, SOAP, WebSocket and async, and orchestrator scheduling and persistence. The production secret store is still not built.
- The Windows build (`build.ps1`) has not been run on these tranches. You said you will build it later.


## Phase 13 tranche — upload and body bounds (ABUSE-005)

Branch: `feature/api-bas-phase13` (from `main`). Two framework changes and one scenario, bringing the total to twenty-seven.

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-ABUSE-005 | Unbounded attachment upload | property_level | FAIL, exploited (2 MiB accepted) | PASS (413 above 1 MiB) | STATE_CHANGE_SANDBOX |

New flaw: `LAB-ABUSE-UPLOAD-001`.

### Framework changes

- **Filler placeholder.** A body may contain `{filler:N}`, which expands to N bytes when the request is sent. The contract refuses any N above `MaxFillerBytes` (5 MiB) when the scenario loads. This keeps large bodies out of the YAML.
- **Accepted-size check.** A scenario may set `max_accepted_bytes`. The grader reads `accepted_bytes` from each attack response. A larger value is exploitation. It shares the same counting path as the granted page size, which now reads any integer field through one helper.

### Limitation

The lab reports the accepted size and does not store the attachment. The check therefore grades what the server accepted, not what it kept. Storage exhaustion itself is not measured.

### Tests

`go test ./internal/apibas/... -count=1`: all packages pass. New: `runner/phase13_test.go` (vulnerable FAIL, fixed PASS with 413) and `contract/filler_test.go` (a filler above the bound is refused).

### CLI smoke test (both modes, all twenty-seven scenarios)

Vulnerable: 27 of 27 FAIL, exploited. Fixed: 27 of 27 PASS, not exploited. Token check against the lab logs: zero matches.

### Still open

- Twenty-seven scenarios of roughly 50 Phase 2 sub-techniques.
- Item-count pagination evidence needs a fixture with more records than the cap.
- ABUSE-002 (expensive requests): needs repeated timing measurement, which is not deterministic on a shared machine. Needs a design decision on how to grade latency.
- ABUSE-004 (GraphQL depth) and ABUSE-006 to ABUSE-010 depend on protocol or queue adapters, or on a second service in the lab.
- Detection (Phase 4): a fixture SIEM adapter and detection assertions. Every scenario is still `not_evaluated`. Needs a decision on which SIEM the fixture should emulate.
- Protocol adapters for GraphQL, gRPC, SOAP, WebSocket and async. Blueprint section 2 requires these to be reported as `UNSUPPORTED` until they exist.
- Orchestrator scheduling and persistence, and the production secret store. These belong outside the lab and need their own design.
- The Windows build (`build.ps1`) has not been run on these tranches. You said you will build it later.


## Phase 14 tranche — ABUSE-002 timing harness (step 1 of the detection and timing plan)

Branch: `feature/api-bas-phase14` (from `main`). Scenario count is twenty-eight. This tranche covers the measurement harness and ABUSE-002. The Elastic fixture and the pagination fixture are not started (see Still open).

| ID | Sub-technique | Claim | Vulnerable | Fixed | Side effect |
|---|---|---|---|---|---|
| API-BAS-ABUSE-002 | Expensive report request without a period limit | property_level | FAIL, exploited (timing and resource) | PASS (400, refused before work) | READ_ONLY |

New flaw: `LAB-ABUSE-REPORT-001`.

### Measurement environment

- CPU: Intel Core i5-8250U, 1.60 GHz, 4 cores, 8 logical processors
- Memory: 8 GB
- OS: Windows 10 Pro 10.0.19045
- Go: go1.26.8 windows/amd64
- Lab: in-process `httptest` server, loopback only, same process as the test. Warm-up and measured requests share the process.
- Workload: `GET /api/orders/report?periods=200` (attack) against `GET /api/orders/{id}/status` (baseline, owner token).

### The work is real

Each period is a chain of SHA-256 rounds over a 1 KiB buffer, 2,000 rounds per period. The cost is measured from the work done, not declared. The response reports `work_units` (periods × 2,000) for the resource check.

### Frozen policy (declared in the scenario file)

| Setting | Value | Reason |
|---|---|---|
| `ceiling_ms` | 250 | Vulnerable attack medians sit near 1,340 ms, about 5× the ceiling, so a machine twice as slow still crosses. A fixed request is refused in under 1 ms. The ceiling sits between those two cases. |
| `min_ratio` | 5 | Attack median must be at least five times the baseline median. The observed ratio is about 8,000. |
| `max_cv` | 0.5 | A round whose coefficient of variation exceeds this is noisy and is ERROR, never PASS. Observed CV is 0.006 to 0.061. |
| `warmup` | 3 | Requests discarded before each round. |
| `trials` | 10 | Paired samples per round. |
| `rounds` | 3 | Every round must agree. |
| `max_work_units` | 24000 | Resource limit, graded independently of timing. |

### Repeatability (three full runs of each variant)

Vulnerable, all nine rounds:

- Median attack latency: 1,320 to 1,357 ms
- p95 attack latency: 1,333 to 1,623 ms
- Median baseline: 0.15 to 0.19 ms (batch of 50 per trial)
- Ratio: 7,105 to 8,989
- CV: 0.006 to 0.061
- Timing verdict: FAIL/exploited in all three runs

Fixed, all three runs: attack refused with 400 in every trial, so the timing comparison does not apply. Outcome PASS/not_exploited in all three runs.

### Harness findings that changed the design

1. **Timer quantization.** On this machine, single requests under about 0.5 ms are quantized. The first measurement put the cheap baseline at 0.00 ms, which made the ratio meaningless. Baseline samples are now the mean of 50 back-to-back requests per trial.
2. **Resource limit masked timing.** The first vulnerable run was decided by the work-unit check before the timing grader ran. The report now records the timing verdict separately (`timing_verdict`), so both results are visible. The outcome still follows the resource check, as the independence rule requires.
3. **Fail closed.** A noisy round (CV above `max_cv`) grades as ERROR with reason `NOISY_MEASUREMENT`. Rounds that disagree grade as ERROR with `INCONSISTENT_ACROSS_ROUNDS`. Neither can be a PASS.

### Tests

- `go test ./internal/apibas/latency/`: statistics (median, nearest-rank p95) and grading (every round crosses, every round within, disagreeing rounds, noisy rounds, no rounds).
- `go test ./internal/apibas/runner/ -run TestABUSE002Repeatability`: three runs of each variant. About 160 seconds, skipped under `-short`. The vulnerable timing verdict is asserted to be FAIL/exploited on every run.

### CLI smoke test (both modes, all twenty-eight scenarios)

Vulnerable: 28 of 28 FAIL, exploited. Fixed: 28 of 28 PASS, not exploited. Token check against the lab logs: zero matches.

### Limitations

- The fixed build's timing is only measured as a refusal. The within-budget path (a report of 12 periods or fewer, which is allowed and should finish under the ceiling) is not yet measured. It is the next measurement to add.
- All measurements are in-process on one machine. The threshold is frozen for this declared environment only. Another machine needs its own baseline measurement before the threshold is trusted there.

### Still open

- Detection (Phase 4): the Elastic-emulating fixture and detection grading contract. Not started.
- Pagination fixture with more records than the cap, for item-count evidence. Not started.
- ABUSE-004 and ABUSE-006 to ABUSE-010: need protocol adapters or a second service. Left unimplemented until those exist.
- Unsupported protocol adapters (GraphQL, gRPC, SOAP, WebSocket, async): must be reported as UNSUPPORTED. Not yet wired into the report.
- Orchestrator scheduling and persistence, and the production secret store.
- The Windows build (`build.ps1`) has not been run on these tranches.


## Phase 15 tranche — detection fixture, item-count pagination, unsupported-protocol manifest

Branch: `feature/api-bas-phase15` (from `main`). This tranche covers steps 2, 3 and 4 of the detection-and-timing plan. Scenario count stays at twenty-eight, because the pagination scenario is re-run on a new fixture, not added.

### Step 2 — Elastic Security detection fixture (fixture-validated, not live)

- A vendor-neutral `detect` package. Its `Adapter` interface is what Sentinel, Splunk and QRadar adapters would implement. Only the Elastic-style fixture exists so far.
- Events are validated before any are stored: sequence numbers are positive and unique, and correlation ID, action, outcome, identity and status are present and in range.
- Three threshold rules: repeated 401 failures (high, fires on the third), throttled requests (medium, fires on the first), and server faults (low, fires on the first). Rules are evaluated per correlation ID, so one run never sees another run's events.
- The lab writes one access event per product request, tagged with the run's `X-BAS-Run` header. Lab administration routes are not recorded. Events carry no tokens.
- The runner grades the detection axis after the exploitability run. It never changes exploitability. Every detection result carries the provenance label `fixture-validated: elastic-security detection fixture; not validated against a live SIEM`.
- Detection block added to two scenarios.

| Scenario | Expected rule | Vulnerable | Fixed | Reading |
|---|---|---|---|---|
| API-BAS-ABUSE-001 | APIBAS-REL-001 (high) | detected | detected | The SIEM sees the failed attempts whether or not the control holds. |
| API-BAS-AUTHZ-001 | APIBAS-REL-001 (high) | missed | missed | Coverage gap. A single cross-tenant request is invisible to a threshold rule. |

The AUTHZ-001 miss is recorded, not hidden. Closing it needs the lab to emit the object owner on each access event, and a rule that uses it.

### Step 3 — pagination with enough records to test the cap

- New `orders-paged` fixture: the owner (customer-b) holds 151 orders, against a fixed-build cap of 100. Each paged order has its own protected values, so a leak is attributable to one order.
- ABUSE-003 now runs on this fixture and grades an item-count check (`max_items_returned: 100`) as well as the granted page size. The vulnerable build returns all 151 owned orders in one page.
- The runner command-line tool needed the fixture added to its own map. The first clean smoke run failed for ABUSE-003 on that gap, and the fix is in the same commit.

### Step 4 — explicit gaps, unsupported protocols

- `docs/api-bas-coverage.md` lists every implemented scenario, every detection result, and every item not implemented, each with the dependency that blocks it: ABUSE-004, ABUSE-006 to ABUSE-010, and the pagination item count on the default fixture.
- A scenario that declares a protocol with no adapter (graphql, grpc, soap, websocket, async) loads, and is reported `SKIPPED / UNSUPPORTED_PROTOCOL`. It is never counted as covered.

### Tests

- `go test ./internal/apibas/... -short`: all packages pass.
- `detect/detect_test.go`: invalid events rejected; duplicate sequence numbers rejected; third failure fires and second does not; correlation isolation; throttled rule; severity and correlation in grading; results do not depend on ingestion order.
- `runner/phase15_test.go`: detection is separate from exploitability; a fixed-build ABUSE-001 is still detected and still PASS; an unsupported protocol is SKIPPED as UNSUPPORTED; the provenance disclaims live validation.
- `runner/phase12_test.go`: ABUSE-003 on the paged fixture, FAIL on the vulnerable build and PASS on the fixed build.

### CLI smoke test (both modes, all twenty-eight scenarios)

Clean run after the fixture-map fix: vulnerable 28 of 28 FAIL, exploited; fixed 28 of 28 PASS, not exploited. Detection as above. Token check against the lab logs: zero matches.

Note: the first smoke run in this tranche reported 27 of 28 with ABUSE-003 failing on `unknown fixture "orders-paged"`. That was the runner's fixture map, not the lab. The clean run above is the one recorded.

### Still open

- Detection: one fixture only. The Sentinel, Splunk and QRadar adapters are not built. The single-request cross-tenant rule needs the lab to emit object ownership.
- ABUSE-004, ABUSE-006 to ABUSE-010: not implemented (see the coverage manifest).
- Protocol adapters for GraphQL, gRPC, SOAP, WebSocket and async: not built. Reported UNSUPPORTED.
- Timing threshold: frozen for one machine only.
- Orchestrator scheduling and persistence, and the production secret store: not built.
- The Windows build (`build.ps1`) has not been run on these tranches.


## Phase 16 tranche — closing the two open items

Branch: `feature/api-bas-phase16` (from `main`). Scenario count stays at twenty-eight.

### 1. AUTHZ-001 detection gap closed

- The lab records the owner of the order each request touches (`object_owner`). Requests that name no order carry no owner.
- New rule APIBAS-REL-004 (access to an object owned by another identity, high, fires on the first match). It fires on the attempt, whether the request was allowed or denied. The owner reading their own order does not fire it.
- AUTHZ-001 now grades `detected` in both builds. Previously it was `missed`, because the threshold rule on repeated failures cannot see a single request.
- Tests: `detect/owner_test.go` covers allowed and denied cross-identity attempts, owner access, and events with no owner.

### 2. Timing threshold tied to one machine: now fails closed

- A timing scenario declares the baseline it was calibrated against (`calibration: baseline_ms, tolerance`). ABUSE-002 declares 0.15 ms with tolerance 4.
- After the rounds are measured, the median baseline is checked against the declared band. Outside the band the timing verdict is `ERROR/ENVIRONMENT_MISMATCH`. It is never graded as a timing pass or fail.
- Tests: `latency/calibration_test.go` covers the band edges, a machine four times slower than declared, no samples, and the reason being an ERROR.
- Limit: calibration checks the baseline only. It does not prove the attack-side ceiling holds on other hardware. Another machine is recalibrated by re-measuring and updating the declared baseline. The threshold is not adjusted automatically.

### Clean smoke run

Vulnerable: 28 of 28 FAIL, exploited. Fixed: 28 of 28 PASS, not exploited. Detection: AUTHZ-001 detected and ABUSE-001 detected, in both builds. Token check: zero matches.

### Still open

- Detection: one fixture (Elastic Security). Sentinel, Splunk and QRadar adapters are not built.
- ABUSE-004, ABUSE-006 to ABUSE-010 and the protocol adapters: not implemented. See `docs/api-bas-coverage.md`.
- Timing: calibration covers the baseline only. The threshold is frozen for the measured machine and will report ERROR elsewhere until recalibrated.
- Orchestrator scheduling and persistence, the production secret store, and the Windows build (`build.ps1`) on these tranches.


## Phase 18 tranche — ABUSE-002 hardware-robust grading and reproducible calibration

Branch: `feature/api-bas-phase18` (from `main`). Scenario count stays at twenty-eight.

### Grading order (latency.Assess)

1. Sample sufficiency: fewer than the declared trials per round is INCONCLUSIVE (`INSUFFICIENT_SAMPLES`).
2. Baseline band: each round's baseline median must lie in `[baseline_ms/tolerance, baseline_ms*tolerance]`. Outside it is ERROR (`ENVIRONMENT_MISMATCH`).
3. Attack measurement band: each round's attack median and p95 must be at or below `attack_max_ms`. Above it is ERROR (`ATTACK_MEASUREMENT_INVALID`).
4. Variance: a round is noisy only when its CV exceeds `max_cv` **and** its spread exceeds `noise_floor_ms`. Noise is INCONCLUSIVE (`EXCESSIVE_VARIANCE`).
5. Effect size and consistency: a crossing round must reach `min_ratio` (`BELOW_EFFECT_SIZE`), and all rounds must agree (`INCONSISTENT_ACROSS_ROUNDS`).
6. Decision: all rounds at or above the ceiling is FAIL. All rounds below it is PASS.

INCONCLUSIVE is reported as SKIPPED with inconclusive exploitability. It is never a pass.

### Never a security PASS on a failed validity check

- The calibration check runs before any traffic. A missing record or a declared value that differs from the record is ERROR (`CALIBRATION_MISSING` / `CALIBRATION_MISMATCH`).
- The old code skipped the baseline check when the control refused the attack. That path is gone. Refusal now goes through the same grading.
- `timingOutcome` is the only place a timing PASS is produced. ERROR is never overridden. A work-unit breach is a FAIL, unless the timing verdict is ERROR.
- `timing_test.go` checks that no non-PASS verdict can become PASS.

### Versioned calibration records

- `internal/apibas/calibration/records/API-BAS-ABUSE-002.v<N>.json`, embedded in the binary.
- Each record stores the operator's machine label, GOOS/GOARCH, CPU count, Go version, workload, sample count, measured baseline median/p95/CV, and every threshold the grade depends on.
- Records are write-once. `calibration.Write` uses an exclusive create and requires the next version and a `supersedes` link. v1 is kept on disk.
- Recalibration is explicit: `apibas-runner -calibrate -scenario API-BAS-ABUSE-002 -machine <label>`. It writes a record and prints the catalog values to change. It runs no scenario and widens nothing.
- The catalog's declared values must match the record exactly. Changing a threshold without a new record fails closed.

### Decision for review: absolute noise floor

- The first v1 run showed the fixed build as INCONCLUSIVE (`EXCESSIVE_VARIANCE`). The fixed build answers in sub-millisecond time, so its CV reflects Windows timer quantization, not real spread.
- Fix: a CV breach only counts above a declared 1 ms absolute spread. The ceiling is not changed. Noisy vulnerable measurements are still INCONCLUSIVE.
- Recorded in v2 with `noise_floor_ms: 1`. v1 is retained.
- This is a judgment call. If the reviewer rejects it, the fixed build reports INCONCLUSIVE, and the scenario's negative test fails rather than passing.

### Calibration measurements (this machine)

- v1 measured baseline median 0.1448 ms, p95 0.1984 ms, CV 0.149, 30 samples.
- v2 declares baseline 0.14 ms with tolerance 4x, ceiling 250 ms, min ratio 5, max CV 0.5, attack band 5000 ms, noise floor 1 ms.
- Vulnerable build: `decision:FAIL`. Fixed build: `decision:PASS`.

### Tests

- `latency/assess_test.go`: deterministic, no network. Covers baseline drift (whole set and one round), attack drift (median and p95), noisy attack and baseline, insufficient samples (per-round and no rounds), boundaries (ceiling, attack band, baseline band), effect size, mixed rounds, timer-jitter below the floor, vulnerable and fixed variants, a never-PASS-on-invalid table, and determinism.
- `calibration/calibration_test.go`: first version, supersession, refusal of wrong versions, machine label required, exclusive write, missing record.
- `runner/timing_test.go`: the outcome mapping invariant, and calibration gate against the shipped record (accept, drifted threshold, unknown version).

### Smoke run

Vulnerable 28 of 28 FAIL, exploited. Fixed 28 of 28 PASS, not exploited. Detection unchanged. Token check: zero.

### Still open

- Calibration measures the baseline only. The attack-side ceiling is not proven on other hardware.
- A calibration is valid only for the machine it was measured on. Other machines fail closed until they run `-calibrate` and the reviewer updates the catalog.
- The noise floor is fixture-specific, as the spec asks.


## Phase 19 tranche - two-stage calibration: environment qualification, then attack-versus-fixed separation

Branch: `feature/api-bas-phase19` (from `main`). Scenario count stays at twenty-eight.

### Model

1. **Environment qualification.** On the target machine, the vulnerable and fixed builds are measured interleaved, on the same workload, with the order alternating each trial. The record stores every raw sample for both builds, the baseline, the lab-reported work units, and the verdict.
2. **Attack-versus-fixed separation.** The verdict requires a Mann-Whitney test (two-sided, normal approximation) at the declared alpha, and a ratio of vulnerable to fixed median at the declared minimum degradation. Both are declared before measurement.
3. **Runtime grading** is unchanged: the frozen ceiling and the per-run validity checks.

### Qualification checks (latency.Qualify)

| Check | Failure reason | Effect |
|---|---|---|
| Sample count per round | CAL_INSUFFICIENT_SAMPLES | unqualified |
| Baseline band, both builds | CAL_BASELINE_OUT_OF_BAND | unqualified |
| Attack band, both builds | CAL_ATTACK_OUT_OF_BAND | unqualified |
| Variance (CV and absolute floor) | CAL_EXCESSIVE_VARIANCE | unqualified |
| Vulnerable reaches the budget | CAL_VULNERABLE_BELOW_BUDGET | unqualified |
| Fixed stays within the budget | CAL_FIXED_OVER_BUDGET | unqualified |
| Separation p-value | CAL_INSUFFICIENT_SEPARATION | unqualified |
| Ratio at or above minimum degradation | CAL_BELOW_MIN_DEGRADATION | unqualified |

Every failed check is recorded, not only the first.

### Runtime gate (not_evaluated, never a security verdict)

- No record for the declared version: `CALIBRATION_MISSING`.
- Record unqualified: `CALIBRATION_NOT_QUALIFIED`.
- Machine label, OS, architecture, CPU count or Go version differs from the record: `REQUALIFICATION_REQUIRED`.
- Declared values differ from a qualified record: `CALIBRATION_MISMATCH`, an ERROR, because it means the policy was edited without recalibration.

All but the mismatch case are reported as SKIPPED with the reason and marked not_evaluated. The shipped catalog is never graded against an unqualified or foreign record.

### Integrity

- Records are write-once, embedded in the binary, and checked on read. `Get` recomputes the verdict, the p-value and the ratio from the stored samples and thresholds. An edited sample, a flipped verdict, an altered threshold, or a qualified claim with no samples fails with `ErrIntegrity`.
- `Write` verifies a record before it writes, and encodes before creating the file, so a record that cannot be encoded leaves nothing behind.
- Recalibration: `apibas-runner -calibrate -scenario API-BAS-ABUSE-002 -target <vulnerable> -fixed-target <fixed> -machine <label>`. It writes the next version and names the one it supersedes. It changes no threshold.

### Measurements on this machine (`lab-i5-8250u-win10-go1.26.8`)

- Calibration v4: vulnerable median 1355.9 ms, fixed median at the timer floor (0 ms, samples are 0 or about 0.5 ms), separation p = 2.9e-11, qualified.
- Catalog declares v4 with baseline 0.17 ms, tolerance 4x, ceiling 250 ms, min ratio 5, max CV 0.5, attack band 5000 ms, noise floor 1 ms, alpha 0.01, minimum separation ratio 5.
- Vulnerable build: `decision:FAIL`. Fixed build: `decision:PASS`. Same machine label, other machine label: `not_evaluated/REQUALIFICATION_REQUIRED`.
- Smoke run: vulnerable 28 of 28 FAIL, fixed 28 of 28 PASS, token check zero.

### Decisions for review

- **Fixed median at zero.** The fixed build's refusal is faster than the clock resolves. The ratio's denominator is floored at the 1 ms noise floor. The ratio then cannot exceed what the clock can resolve, so it can only understate degradation. The stored ratio is verified like the p-value.
- **v3 superseded.** The first two-build calibration (v3) stored an infinite ratio under the earlier rule. Under the corrected rule its stored ratio fails verification. It stays on disk as history, and v4 supersedes it. Nothing references v3.
- **Declared baseline.** The baseline band is centred on the calibration's pooled baseline median, rounded to 0.01 ms. This characterises the environment. It is not a security threshold.

### Tests (deterministic, no timing)

- `latency/qualify_test.go`: clean qualification and determinism; separation at strict alpha; Mann-Whitney identical and disjoint samples, and the empty case; minimum-degradation boundary; vulnerable at and below the ceiling; fixed at the ceiling; baseline drift; attack out of band; noisy runs; sub-floor jitter not treated as noise; short samples; a missing build; every failure reported; sub-floor fixed median uses the floor.
- `calibration/integrity_test.go`: sealed records verify; tampered samples, flipped verdicts, wrong p-value, edited thresholds, write refusal, qualified-without-samples, and legacy unqualified records.
- `calibration/calibration_test.go`: versioning, supersession, exclusive writes, machine label, missing records.
- `runner/timing_test.go`: the never-PASS mapping, the shipped catalog never mismatching its record, drifted thresholds refused, unknown versions refused.

### Still open

- Calibration is valid for this machine only. Any other machine is refused until it runs `-calibrate` and the catalog is updated.
- The machine label is operator-asserted. Hardware identity is not read from the OS, so a relabelled machine is not detected.
- The separation test uses a normal approximation, without a tie correction. Timing samples in nanosecond resolution rarely tie, but the approximation is not exact for small samples.
- Work units were 400000 for the vulnerable build and 0 for the fixed build. The resource check is independent of timing.
- The attack-side ceiling is still a fixture-specific budget, not a universal threshold.


## Phase 20 tranche - environment fingerprint, tie-corrected separation, explicit requalification

Branch: `feature/api-bas-phase20` (from `main`). Scenario count stays at twenty-eight.

### Decisions implemented

| Decision | Implementation |
|---|---|
| Unqualified environment is ERROR, not a security verdict | Every calibration refusal (missing, unqualified, mismatched, workload, fingerprint) returns ERROR with its reason. The runtime gate no longer produces SKIPPED. |
| Operator label is not identity | The label is recorded for display only. Only the environment fingerprint is compared. Renaming a machine does not requalify it (tested; confirmed live with `renamed-laptop`). |
| Fingerprint from OS/hardware attributes | `calibration/fingerprint.go`: Go runtime (GOOS, GOARCH, Go version, CPU count); Windows: `kernel32!GlobalMemoryStatusEx` (memory), `ntdll!RtlGetVersion` (OS build), `PROCESSOR_IDENTIFIER` (CPU model); Linux: `/proc/cpuinfo`, `/proc/meminfo`, `/etc/os-release`. |
| Record which attributes were available and verified | Each attribute stores its source. Attributes the platform cannot read are listed as `unavailable`, and that list is part of the digest. |
| Fingerprint is drift detection, not proof | Documented in the code and here. A local administrator can change any of these values, so deliberate spoofing is not detected. |
| Tie-corrected Mann-Whitney | `MannWhitneyP` assigns average ranks to ties and reduces the variance by the tie term. |
| Minimum sample requirements | `min_pooled_samples: 20` per build (30 in the current calibration). Declared before measurement and enforced in `Qualify`. |
| Identical measurements handled explicitly | All-identical values on both builds fail with `CAL_NO_RESOLUTION`. The p-value is 1. |
| Minimum effect size and false-positive rate | Declared in the catalog before measurement: `min_separation_ratio: 5` and `alpha: 0.01`. Significance alone is not enough. |
| Requalification policy | Explicit. The fingerprint digest, the workload string (`workloadFor`), the thresholds, and the record version each have a separate check and reason. |
| Calibration cannot change the budget | Declared thresholds must equal the record field for field, or the gate returns `CALIBRATION_MISMATCH`. Calibration writes only the environment characterisation. |

### Runtime gate, in order

1. Record missing: `CALIBRATION_MISSING` (ERROR).
2. Record fails integrity: `CALIBRATION_MISMATCH` (ERROR). This covers edited samples, a flipped verdict, an edited ratio or p-value, an edited fingerprint, and a record with no fingerprint that claims samples.
3. Record unqualified: `CALIBRATION_NOT_QUALIFIED` (ERROR), with the failed checks listed.
4. Declared thresholds differ from the record: `CALIBRATION_MISMATCH` (ERROR).
5. Workload differs from the record: `REQUALIFICATION_REQUIRED` (ERROR).
6. Environment fingerprint differs from the record: `REQUALIFICATION_REQUIRED` (ERROR).

Only a passing gate reaches the attack. Then the baseline, attack, variance and effect checks of `latency.Assess` apply, as before.

### Statistics

- Tie-corrected Mann-Whitney, normal approximation, two-sided. Exact permutation was not used. With 30 samples per build it needs about 10^17 arrangements, so it is out of reach. The approximation is the reason for the minimum sample count, and the limit is stated.
- Tests cover disjoint tied groups (separated), identical tied groups (not separable), all-identical values (no resolution), the pooled minimum at its boundary, and determinism.

### Calibration v5 on this machine

- Fingerprint: CPU model "Intel64 Family 6 Model 142 Stepping 10, GenuineIntel" (env, system-set), memory 8,415,367,168 bytes (kernel32), OS build 10.0.19045 (ntdll), Go go1.26.8, 8 CPUs. Unavailable: none.
- Vulnerable median 1366.1 ms. Fixed median 0 ms (timer floor). Ratio 1366.1 (denominator floored at the 1 ms noise floor). p = 1.2e-11. Qualified.
- Catalog declares v5 with baseline 0.18 ms.
- Vulnerable build: `decision:FAIL`. Fixed build: `decision:PASS`. Both with a renamed label: unchanged.

### Tests

- `latency/qualify_ties_test.go`: tied separation, tied overlap, all-identical, pooled minimum boundary, determinism.
- `calibration/fingerprint_test.go`: live fingerprint matches itself; every attribute read or listed unavailable; changed memory, CPU or Go version does not match; newly unavailable attribute does not match; label ignored; empty digest never matches; edited attribute inconsistent; record with edited fingerprint fails verification.

### Known limits

- Fingerprint is a drift detector. A deliberate spoof is not detected. It does not prove hardware identity.
- Available-memory and load values are excluded, because they change between runs. Total memory is recorded.
- Hostname is excluded, so a renamed host does not requalify it.
- Only the attributes above are collected. A platform with fewer sources records more `unavailable` entries, and requalifies if they change.
- Calibration is machine-specific. An unqualified environment is ERROR until it is recalibrated.
- The fixture-specific budget (250 ms ceiling, 5x minimum ratio, 1 ms noise floor, 5000 ms attack band) is documented as fixture-specific. It is not a universal API security threshold.
- v3 and v4 remain on disk as history. Neither is referenced. v4 has no fingerprint, so it fails integrity.

### Not yet done

- ABUSE-002 is not yet acceptance-validated on a second qualified environment. Its scenario claim should remain provisional until that passes.


## Phase 21 - second-environment run of the ABUSE-002 runbook (acceptance NOT met)

Environment: a Debian bookworm Linux container (Docker Desktop VM, 2 vCPU, about 6 GB)
on the same physical host as the first calibration. It is a second OS, kernel and runtime
with different CPU count and memory, but it is NOT a second physical machine. Cross-machine
validation stays pending on a physical host.

Code: `main` at `58ba0a80`. Linux binaries cross-compiled from it. For the adopted runs the
catalog was set to v6 for the build only and then restored. The committed catalog still
points at v5.

### Steps

1. **Original calibration rejected.** v5 run in the container: `ERROR/REQUALIFICATION_REQUIRED`.
2. **Explicit calibration.** Both labs, interleaved. Written as v6 with the container's
   fingerprint. `qualified: true`, no reasons. Vulnerable median 1375.8 ms. Fixed median
   0.1998 ms (a real measurement, not the timer floor seen on Windows). Ratio 1375.8 on
   the 1 ms noise floor. Separation p = 2.87e-11. Baseline 0.27 ms.
3. **Adopted** in a build-only copy: catalog at v6, baseline 0.27 ms.
4. **Acceptance runs.** Three separate container starts per variant.

| Run | Vulnerable | Fixed |
|---|---|---|
| 1 | decision:FAIL (attack median 1380.7 ms) | decision:PASS (median 0.253 ms) |
| 2 | decision:FAIL (1372.2 ms) | decision:PASS (median 0.169 ms) |
| 3 | decision:FAIL (1351.0 ms) | variance:SKIPPED / EXCESSIVE_VARIANCE |

### Why the fixed run 3 is inconclusive

Round 2 of fixed run 3 is the only round where the variance gate fired on the attack side.
Its attack median is 0.21 ms, but its p95 is 2.71 ms and its stdev 0.75 ms. In round 1 the
p95 reaches 9.41 ms and the stdev 2.87 ms. Those are tail spikes on a 2-vCPU container
where the lab and the runner share the CPUs. The gate reports noise as noise and returns
INCONCLUSIVE. It does not return PASS. That is the designed behaviour.

### Acceptance

The runbook requires the fixed build to PASS on every repeat. That is not met: 2 of 3
repeats PASS and 1 is INCONCLUSIVE. Per the runbook, the run is recorded as it is and not
repeated until it passes. Thresholds, the noise floor and the sample counts were not changed.

### Refusal reasons recorded

- Step 1: `REQUALIFICATION_REQUIRED` (v5 fingerprint does not match the container).
- Step 4 run 3 (fixed): `EXCESSIVE_VARIANCE` in rounds 0-2 (attack-side tail latency).

### What this does and does not show

- It shows the vulnerable build reproducibly FAILs in this environment (3 of 3), and the
  fixed build PASSes in 2 of 3. Separation in the calibration is large, p about 3e-11.
- It shows the fingerprint detects a different environment and that an unqualified
  environment is refused.
- It does NOT pass the acceptance criterion. ABUSE-002 is not validated on a second
  environment.

### Options, for a decision (not applied)

- Measure in a quieter environment: more vCPUs, or the lab and runner pinned to separate
  CPUs. That changes the measurement method, so it needs a new calibration and a
  documented reason. It is not a threshold change.
- Accept a noisy-environment result as INCONCLUSIVE and treat the environment as not
  qualified for ABUSE-002 security verdicts. That is consistent with the rules.
- Stay with one-machine provisional validation until a physical second machine is available.

### Records

- Calibration v6 (container fingerprint) is committed as history. The catalog still points
  at v5, so the Windows host's runs are unaffected.


## Phase 22 - injection tranche (API-BAS-INJ, Phase 2 P2 IDs)

Branch: `feature/api-bas-phase22`. Scope: the ten Phase 2 injection sub-techniques,
INJ-001, 002, 003, 004, 006, 008, 009, 010, 011, 012. INJ-005 and INJ-007 are Phase 3
and are not included.

### Scenarios

| ID | Sub-technique | Claim | Vulnerable flaw | Fixed control | Side effect |
|---|---|---|---|---|---|
| INJ-001 | SQL/NoSQL predicate injection | cross_identity | `q` with a quote and OR matches every order | exact ID match only | READ_ONLY |
| INJ-002 | Expression injection | cross_identity | expression field with `||` returns every order | expression refused (400) | STATE_CHANGE_SANDBOX |
| INJ-003 | Server-side template injection | cross_identity | caller template rendered on the full record | template refused (400); plain tokens only | STATE_CHANGE_SANDBOX |
| INJ-004 | LDAP filter injection | cross_identity | unescaped wildcard matches every entry | wildcard treated as no match | READ_ONLY |
| INJ-006 | JSON duplicate keys | property_level | first status validated, last applied | duplicate key refused (400) | STATE_CHANGE_SANDBOX |
| INJ-008 | Path traversal | cross_identity | `..` in export name reaches internal records | name must be a plain CSV name (400) | READ_ONLY |
| INJ-009 | Header injection | property_level | note with `;` written into Set-Cookie | note restricted to plain characters (400) | STATE_CHANGE_SANDBOX |
| INJ-010 | SSRF | cross_identity | import fetches an internal path | URL and path sources refused (403) | STATE_CHANGE_SANDBOX |
| INJ-011 | Prototype pollution | property_level | `__proto__` merge rewrites owner_id | reserved key refused (400) | STATE_CHANGE_SANDBOX |
| INJ-012 | Cross-format validation | property_level | form-encoded status skips validation | validation applied to every content type (400) | STATE_CHANGE_SANDBOX |

Every POST scenario is STATE_CHANGE_SANDBOX, because the contract treats any non-GET step as
mutating. Each has a reset cleanup.

### Design choices

- **Fixed-build PASS.** Four fixed routes return an empty 200 (INJ-001, 004, and the
  wildcard and predicate cases). Those scenarios set `clean_is_enforcement: true`, which the
  grader needs to PASS. The others declare a denial status.
- **Ground truth.** Each scenario uses the state and response adapters. A leak counts only
  when a protected value of the owner appears in a response. A state change counts only when
  the attack changes state.
- **Baseline precondition.** Each cross_identity scenario has its baseline identity own the
  object. Both INJ-010 and the others check this, so INJ-010 was first skipped with
  PRECONDITION_MISSING and was corrected to baseline as the owner (customer-b on ORD-2001).
- **Routes in both modes.** The injection routes are registered in both builds. The planted
  flaws exist only in the vulnerable build, and the fixed build refuses or does not interpret
  the injected input.
- **Known limitation, INJ-003.** The preview route checks no owner in either build. The fixed
  build returns only public tokens (id and status) for another customer's order. That is a
  BOLA-shaped gap for public fields, not a protected leak, and it is not graded here.
- **Known limitation, INJ-008.** The vulnerable build also serves another customer's
  public CSV without an owner check. The public data contains no protected values, so no
  finding is raised. It is an access-control gap for a later AUTHZ scenario.

### Verification

- `go build ./internal/apibas/...` and `go vet ./internal/apibas/lab/` pass.
- `go test ./internal/apibas/... -short`: all packages pass, including
  `TestFlawRegistryLinksToCatalog` (it failed before the scenarios existed).
- `TestPhase22_InjectionVulnerableFailsFixedPasses`: all ten scenarios FAIL with exploited
  against the vulnerable build and PASS with control enforced against the fixed build.
- `TestPhase22_InjectionFlawsAreRegistered`: each scenario has a planted flaw.

### Pre-existing failure, not changed in this tranche

`TestABUSE002Repeatability` (in `runner/abuse002_test.go`, skipped under `-short`) fails on
the timing verdict string. The test expects `FAIL/exploited`, and the runner now returns
`decision:FAIL/...`. The test was last changed in Phase 14 (`9bb60d56`), and the verdict
format changed in later phases. The vulnerable build still returns FAIL in its measurements
(decision:FAIL in each round). The test is stale. It was left unchanged because it is a
timing expectation, and changing it needs a decision.

### Coverage after this tranche

- Phase 2 scope now covers 34 of 58 sub-techniques (24 before plus 10 injection). The
  remaining 24 are GWAY 10, AUTHZ 4, DISC 4, DATA 2, ABUSE 2, AUTHN 1 and INTEG 1.
- The QA log's earlier "roughly 50" is an estimate. The blueprint's Phase 2 scope lists 58.

### Still open

- The Windows build (`build.ps1`) has not been run on this tranche.
- The gateway tranche needs a front proxy and raw HTTP client for smuggling and
  request-target tests (GWAY-004, 005). That is an architecture change before the scenarios.


## Phase 23 - gateway tranche (API-BAS-GWAY, Phase 2 P2 IDs)

Branch: `feature/api-bas-phase23`. Scope: GWAY-001, 002, 004, 005, 006, 007, 008, 009, 010,
011. GWAY-003 was already covered. GWAY-012 is Phase 3 and is not included.

### Architecture

The lab is a single listener, so there is no separate gateway process or network hop. The
gateway is a policy layer (`lab/gateway.go`) in front of the routes. Its rules apply only
under `/api/gw/`, so every existing scenario's route is unchanged. Each rule has a
vulnerable branch (carrying a `LAB-GWAY-*` flaw) and a fixed branch.

"Direct backend access" (GWAY-001) is therefore modelled, not network-tested: a request that
reaches a route with the gateway's identity header and skips the gateway's checks. The
scenario says so in its description.

### Scenarios

| ID | Sub-technique | Claim | Vulnerable flaw | Fixed control | Denied |
|---|---|---|---|---|---|
| GWAY-001 | Direct access through a forged identity header | cross_identity | identity header replaces the caller's credential | header ignored | 404 |
| GWAY-002 | Undocumented route without gateway policy | authentication | `/api/gw/orders/{id}/legacy` served | route absent | 404 |
| GWAY-004 | Encoded path bypasses the ops policy | function_level | rule matches the escaped path; `%6fps` reaches ops | rule matches the decoded path | 403 |
| GWAY-005 | Duplicate Content-Type | property_level | two Content-Type headers; handler reads the last as a form | refused (400) | 400 |
| GWAY-006 | Forwarded host trusted | function_level | `X-Forwarded-Host: ops.internal` skips the ops rule | header ignored | 403 |
| GWAY-007 | Encoded space evades the WAF | cross_identity | WAF matches the raw query | WAF matches the decoded query | 403 |
| GWAY-008 | No request schema | property_level | unexpected `status` field applied | unknown field refused | 400 |
| GWAY-009 | Rate limit keyed on a client header | function_level | counter keyed on `X-Forwarded-For` | counter keyed on run and caller | 429 |
| GWAY-010 | Legacy region node without credential | authentication | `X-Gateway-Region: legacy` skips the credential | credential required everywhere | 401 |
| GWAY-011 | Fail-open on authz store outage | cross_identity | store down: request allowed | store down: refused | 403 |

### Runner and contract changes

- `contract.Step.ExtraHeaders` appends a header (a duplicate name). It is needed for GWAY-005.
- `{n}` in a header value is replaced by the attempt number on each attack repeat. GWAY-009
  rotates `X-Forwarded-For` this way. Only the attack step repeats, so only the attack's
  headers are expanded.
- `Preconditions.LabFaults` requires named faults to be active. If a fault is missing, the
  scenario is skipped as PRECONDITION_MISSING before any traffic is sent.
  `LabAdmin.ActiveFaults` reads them from `GET /lab/faults`. The lab takes them from the
  `-fault` flag. A scenario cannot set a fault itself, because setup steps use the attacker's
  credential and the lab's admin credential is not available to them.

### Decisions to review

- **GWAY-011 needs the lab started with `-fault authz-store-down`.** Without it the scenario
  is SKIPPED, never counted. The owner's read in the baseline uses the direct route
  `/api/orders/{id}`, because the gateway route fails closed for everyone while the fault is
  active.
- **Fail-closed returns 403, not 503.** The contract accepts only 4xx codes as denials. A
  denied decision is a refusal, so 403 with the reason "authorization decision unavailable".
- **Gateway ID lookup uses the path.** The gateway runs before the mux, so the order ID is
  read from the request path. This was a real defect found by the tests: the owner's baseline
  returned 404 and the scenario was skipped.
- **Anonymous steps.** A step with `auth: none` must name the identity `anonymous`
  (contract rule). GWAY-001, 002 and 010 use it.
- **GWAY-001's attack uses the attacker's own valid token.** The vulnerable identity header
  replaces the credential, so the attacker's token is not what decides the caller. The fixed
  build ignores the header, and the attacker's own token does not own the order (404).

### Verification

- `go vet` on `internal/apibas/...` and both commands passes. The tests pass with `-short`.
- `TestPhase23_GatewayVulnerableFailsFixedPasses`: nine scenarios FAIL with exploitation
  against the vulnerable build and PASS with control enforced against the fixed build.
- `TestPhase23_FailOpenNeedsTheFault`: without the fault GWAY-011 is SKIPPED with
  PRECONDITION_MISSING.
- `TestPhase23_FailOpenVulnerableFailsFixedPasses`: GWAY-011 FAILs under the fault in the
  vulnerable build and PASSes in the fixed build.
- `TestPhase23_GatewayFlawsAreRegistered`: each scenario has a planted flaw.
- The existing scenarios pass unchanged. The gateway does not touch their routes.

### Limitations

- The lab has one listener, so GWAY-001 does not test a network-level bypass. A deployed
  gateway would need a second-listener test.
- The rate-limit counters grow for the life of the lab (keyed per run). This is acceptable
  for a lab and is noted here so it is not copied into a production design.
- GWAY-005's duplicate header is a lab-specific ambiguity: the handler reads the last header.
  Real request-smuggling (`Content-Length` versus `Transfer-Encoding`) needs a raw HTTP client
  and is not covered here.
- `TestABUSE002Repeatability` still fails when run without `-short`. It was already failing
  (see Phase 22). This tranche does not change it.

### Coverage after this tranche

- Phase 2 scope now covers 44 of 58 sub-techniques. Remaining 14: AUTHZ 005, 008, 009, 011;
  DISC 001, 004, 007, 008; DATA 002, 008; ABUSE 008, 009; AUTHN 006; INTEG 004.

### Still open

- The Windows build (`build.ps1`) has not been run on this tranche.
- Running GWAY-011 in a real lab needs the operator to start the lab with `-fault`.


## Phase 24 - authorization tranche (API-BAS-AUTHZ 005, 008, 009, 011)

Branch: `feature/api-bas-phase24`. Scope: the four remaining Phase 2 AUTHZ IDs. AUTHZ-001,
002, 003, 004, 006, 007, 010 were already covered.

### Scenarios

| ID | Sub-technique | Claim | Vulnerable flaw | Fixed control | Denied |
|---|---|---|---|---|---|
| AUTHZ-005 | Cross-branch access | cross_identity | branch listing returns another branch's full records | caller's branch must match | 403 |
| AUTHZ-008 | Group and scope inconsistency | function_level | group name "support" honoured as the audit:read scope | scope required | 403 |
| AUTHZ-009 | Read vs delete permission | cross_identity | DELETE skips the owner check that the read route performs | owner required | 403 |
| AUTHZ-011 | Cache-based leakage | cross_identity | owner's view cached in a cache shared by every caller, keyed by path | per-owner, not shared | 404 |

Routes live under `/api/authz/` and do not change the routes of other scenarios. Each route
carries a `LAB-AUTHZ-*` flaw. The shared cache is cleared on reseed.

### Contract change, for review

- The contract allowed only GET, PATCH and POST. AUTHZ-009 needs DELETE, because the
  read-versus-delete difference is the point of the scenario. I allowed DELETE with no
  body requirement, the same as GET. Mutating is still determined by the method, so a DELETE
  step must be in a STATE_CHANGE_SANDBOX scenario, which the existing side-effect rule
  enforces.

### Verification

- `go vet` and `go test ./internal/apibas/... -short` pass.
- `TestPhase24_AuthzVulnerableFailsFixedPasses`: all four FAIL with exploitation against the
  vulnerable build and PASS with control enforced against the fixed build.
- `TestPhase24_AuthzFlawsAreRegistered`: each scenario has a planted flaw.

### Limitations

- AUTHZ-011 models a shared cache inside the lab process. It does not test a real CDN or
  proxy cache, which would need a separate cache layer.
- AUTHZ-008's "support" group is a lab convention. The real policy source is not modelled.

### Coverage after this tranche

- Phase 2 scope now covers 48 of 58 sub-techniques. Remaining 10: DISC 001, 004, 007, 008;
  DATA 002, 008; ABUSE 008, 009; AUTHN 006; INTEG 004.

### Still open

- The Windows build (`build.ps1`) has not been run on this tranche.


## Phase 25 - discovery tranche (API-BAS-DISC 001, 004, 007, 008)

Branch: `feature/api-bas-phase25`. Scope: the four remaining Phase 2 DISC IDs. DISC-002, 003
and 005 were already covered.

### Scenarios

| ID | Sub-technique | Claim | Vulnerable flaw | Fixed control | Denied |
|---|---|---|---|---|---|
| DISC-001 | Orphaned route absent from the spec | cross_identity | `/api/orphan/orders/{id}` served without an ownership check | route absent | 404 |
| DISC-004 | Spec versus deployed behaviour drift | authentication | `/api/drift/orders/{id}` declared bearer-protected, served with no credential | bearer and owner required | 401 |
| DISC-007 | Exposed documentation | authentication | `/docs` served publicly with a real record as its example | route absent | 404 |
| DISC-008 | Improper error handling | authentication | not-found response carries `X-Backend-Host` | generic not-found | 404 |

The OpenAPI document is served in both builds. Publishing a spec is normal, so it is not a
finding. The drift in DISC-004 is between the spec's declared security and the deployed route.

### Contract gaps found while writing

- Every ground truth must include the state adapter. DISC-008 first omitted it and was
  corrected.

### Verification

- `go vet` and `go test ./internal/apibas/... -short` pass.
- `TestPhase25_DiscoveryVulnerableFailsFixedPasses`: all four FAIL with exploitation against
  the vulnerable build and PASS with control enforced against the fixed build.
- `TestPhase25_DiscoveryFlawsAreRegistered`: each scenario has a planted flaw.

### Limitations

- DISC-001 uses the same undocumented-route mechanism as GWAY-002. It differs by being a
  retired route that needs a token, not a gateway-policy gap.
- DISC-007 detects exposure through a protected value in the example. A real docs site may
  leak data in other ways, which the grader would not see.
- DISC-008 is graded by a header signal only. Error bodies that leak other internals are not
  covered by a separate check.

### Coverage after this tranche

- Phase 2 scope now covers 52 of 58 sub-techniques. Remaining 6: DATA 002, 008; ABUSE 008,
  009; AUTHN 006; INTEG 004.

### Still open

- The Windows build (`build.ps1`) has not been run on this tranche.


## Phase 26 - remaining Phase 2 scenarios (DATA-002, DATA-008, ABUSE-008, ABUSE-009, AUTHN-006, INTEG-004)

Branch: `feature/api-bas-phase26`. These are the last six Phase 2 sub-techniques in the scope
lines of blueprint section 10. Each has a vulnerable route and a fixed control.

### Scenarios

| ID | Sub-technique | Claim | Vulnerable flaw | Fixed control | Denied |
|---|---|---|---|---|---|
| DATA-002 | Financial and account fields in statements | cross_identity | statement returns the full record to any caller | owner only, public view | 404 |
| DATA-008 | Weak field-level masking | property_level | masked card, plus the same value unmasked in card_display | masked in every field | clean (2xx, no leak) |
| ABUSE-008 | Automated account creation | function_level | no limit on sign-up | five per run, then 429 | 429 |
| ABUSE-009 | Per-identity throttling gap | function_level | limit keyed on a client-supplied session header | limit keyed on the authenticated caller | 429 |
| AUTHN-006 | Retired API token | authentication | token still accepted after rotation | refused after rotation | 401 |
| INTEG-004 | Unsafe redirect | authentication | any `next` target is sent in a Refresh header | relative paths only | 400 |

### Contract changes

- `{n}` is now also replaced in the request body, not only in headers. ABUSE-008 needs a
  distinct email for each attempt.
- AUTHN-006 uses a setup step (role `setup`) to call `POST /api/keys/rotate`. The fixed build
  records the retired token in a lab-side set, reset with the fixture.

### Verification

- `TestPhase26_RemainingVulnerableFailsFixedPasses`: all six FAIL with exploitation against the
  vulnerable build and PASS with control enforced against the fixed build.
- `TestPhase26_RemainingFlawsAreRegistered`: each scenario has a planted flaw.
- `go vet` and `go test ./internal/apibas/... -short` pass.

### Limitations, which bound what "covered" means

- **INTEG-004 is covered for the redirect half only.** The sub-technique also covers DNS
  resolution changes. Nothing in the lab changes DNS, so DNS rebinding is not tested. The
  Refresh header models an open redirect. It does not exercise a real browser redirect.
- **ABUSE-009 is a single-identity variant.** The sub-technique describes distributed low-rate
  abuse across identities. A scenario has one attacker identity, so this tests the
  per-identity gap (keying on a client header), not a multi-identity campaign.
- **ABUSE-009 uses the same mechanism as GWAY-009** (a counter keyed on a client-supplied
  value). The scope is different: this is a route-level throttle.
- **ABUSE-008 counts sign-ups but stores no accounts.** The limit is what is measured.
- **DATA-008's unmasked field is the owner's own value.** The masking is tested against the
  owner, not against another customer. Masking that holds only for other callers would not be
  caught.
- **AUTHN-006's rotation issues no replacement key.** It tests that the retired token stops
  working. It does not test the new token.

### Coverage after this tranche

- All 58 Phase 2 sub-techniques in the blueprint scope have a scenario. INTEG-004 is partial, as
  stated above, and is not counted as fully covered. That leaves 57 full and 1 partial.
- The remaining gaps are the ones named in the limitations, and the Windows build.

### Still open

- INTEG-004 DNS-resolution half (needs a resolver the lab controls).
- The Windows build (`build.ps1`) has not been run on any Phase 2 tranche.
- `TestABUSE002Repeatability` still fails without `-short` (see Phase 22).


## Phase 27 - unsupported protocols reported as UNSUPPORTED (blueprint section 2)

Scope: GraphQL, gRPC, SOAP, WebSocket and async. These are declared protocols in the contract,
but no executable adapter exists. Blueprint section 2 says each must be reported as
UNSUPPORTED until its adapter exists.

### What changed

- `grade.Unsupported(reason)` returns an outcome with Result SKIPPED, exploitability
  `unsupported`, control `unsupported`, detection `not_evaluated`, and reason
  `UNSUPPORTED_PROTOCOL`.
- The runner uses it for any scenario whose protocol is not HTTP. The check runs before the
  fixture and precondition checks, and before any request is sent.

### Decision to review

- **The result stays SKIPPED, not a new UNSUPPORTED verdict.** The result set PASS, FAIL,
  ERROR and SKIPPED is shared across the product's scoring. Adding a fifth verdict would change
  scoring everywhere. The word UNSUPPORTED appears in the exploitability, control and reason
  fields, so a reader sees it in the report. If the team wants it as a top-level verdict, that
  is a scoring-model change and needs its own decision.

### Verification

- `TestPhase27_UnsupportedProtocolsAreReportedUnsupported`: for each of the five protocols,
  the result is SKIPPED, exploitability and control are unsupported, the reason is
  UNSUPPORTED_PROTOCOL, and zero API requests reach the lab.
- `TestPhase27_HTTPScenarioIsNotReportedUnsupported`: an HTTP scenario is not affected.
- `go vet` and `go test ./internal/apibas/... -short` pass.

### Not in place yet

- The Phase 3 acceptance line "UNSUPPORTED is not in the covered count" depends on a covered
  count. No coverage metric is computed in the code yet (blueprint section 9). The count of
  scenarios is therefore a document figure, not a report field.
- No catalog scenario currently declares a non-HTTP protocol. The gate is tested with a copy of
  an HTTP scenario that declares one.


## Phase 28 - coverage accounting and protocol catalog entries

Scope: the two items from the review of Phase 27. (1) Coverage counted separately so that
unsupported protocols cannot inflate it. (2) Protocol-specific catalog entries for GraphQL,
gRPC, SOAP, WebSocket and async. No protocol adapter is built. Every protocol remains UNSUPPORTED.

### 1. Coverage accounting (`internal/apibas/coverage`)

Five measures, each with an explicit numerator and the catalog size as denominator:

- Catalogued: scenarios in the catalog. The denominator of every ratio.
- Implemented: scenarios whose protocol has an executable adapter.
- Evaluated: scenarios with a valid verdict (PASS or FAIL with an exploitability value). Never
  SKIPPED or ERROR.
- Validated: valid verdicts in both builds. The vulnerable build FAILs as exploited, and the fixed
  build PASSes with control enforced.
- Excluded: Unsupported (no adapter), Errored (execution or environment failure), Unevaluated
  (implemented, no valid verdict).

The classes partition the catalog. `Consistent()` checks this. An unsupported scenario is in the
catalogue and nowhere else, and a verdict supplied for it is ignored.

Protocol support is decided in one place, `contract.ProtocolSupported`. Scenarios existing in the
catalog do not add support. The runner uses the same check.

### 2. Protocol catalog entries

| ID | Sub-technique | Protocol | Notes |
|---|---|---|---|
| API-BAS-INJ-007 | GraphQL query manipulation | graphql | resolver skips the owner check |
| API-BAS-ABUSE-004 | GraphQL depth and complexity | graphql | nested query should be refused with 400 |
| API-BAS-INJ-005 | XML external entity | soap | DOCTYPE external entity; loopback target only |
| API-BAS-DISC-009 | Inconsistent controls across protocols | grpc | GetOrder skips the REST owner check |
| API-BAS-ABUSE-010 | Queue growth and retry storms | async | repeated publishes, bounded by a limit |
| API-BAS-INTEG-010 | Event tampering | async | altered payload with the original signature |
| API-BAS-AUTHN-011 | WebSocket handshake origin and credential | websocket | **proposed taxonomy addition** |

Contract changes:
- `prerequisites` is required for every non-HTTP scenario, so each one names its adapter,
  fixture and environment before it can run.
- Steps of a non-HTTP scenario describe the protocol operation (method, path, body). No adapter
  sends them until it exists.

### Decision for you: API-BAS-AUTHN-011

The blueprint taxonomy has no WebSocket sub-technique. I added AUTHN-011 so the WebSocket
protocol has a scenario. The entry is marked as a proposed addition in its prerequisites. It
needs an owner decision on the ID and on whether it belongs under AUTHN. If you reject it, the
entry is deleted and the WebSocket protocol has no scenario yet.

### Verification

- `TestPhase28_EveryNonHTTPCatalogScenarioIsUnsupportedWithZeroTraffic`: walks the catalog. For
  each non-HTTP scenario, the result is SKIPPED, the exploitability and control are unsupported,
  the reason is UNSUPPORTED_PROTOCOL, and zero requests reach the lab. A new protocol entry is
  covered without editing the test.
- Coverage tests (`coverage_test.go`):
  - unsupported counts only in the catalogue, and a verdict supplied for it is ignored;
  - adding an adapter raises Implemented, but Evaluated stays the same until a valid verdict
    arrives;
  - Validated needs both builds;
  - an ERROR is excluded and reported separately;
  - the report shows numerators, denominators and exclusions.
- `TestPhase28_MeasuredCoverage` (skipped under `-short`): runs every implemented scenario in both
  builds, using each scenario's fixture and lab faults, and reports coverage from those verdicts.

### Measured result (this host, lab against lab)

```
Catalogued:   69
Implemented:  62/69 (89.9%)
Evaluated:    62/69 (89.9%)
Validated:    62/69 (89.9%)
Exclusions (denominator still includes them):
  unsupported (no adapter):       7
  errored (execution/environment): 0
  unevaluated (implemented, no valid verdict): 0
```

The seven unsupported entries are listed by ID. The 62 implemented scenarios are the HTTP ones,
and all of them are evaluated and validated in both builds. That is the same result the HTTP
suite already asserts, so the HTTP regression is unchanged.

### What this does not establish

- The measured numbers are lab-against-lab. They show the implemented scenarios agree with the
  lab's own vulnerable and fixed builds. They do not show that the lab matches a real product.
- Coverage is over the catalog as it stands. The taxonomy has 110 sub-techniques (section 1) and
  69 catalogued scenarios, so about 41 sub-techniques have no scenario at all. This report does not
  count those as gaps, and it should not be read as covering the taxonomy.
- The unsupported entries have no adapter, so no protocol coverage is gained from them.
- The adapter-later behaviour is tested with a supplied support function, not a real adapter.
  No real GraphQL, gRPC, SOAP, WebSocket or async adapter exists.

### Still open

- The owner decision on API-BAS-AUTHN-011 (above).
- Protocol adapters, one protocol at a time, each with its own acceptance tests before support is
  added to `supportedProtocols`.
- The Windows `build.ps1` run.
- `TestABUSE002Repeatability` without `-short` (pre-existing, see Phase 22).


## Phase 29 - protocol adapters: GraphQL (first of five)

Scope: the first protocol adapter, one at a time, as agreed. GraphQL is supported because its
adapter is registered in `internal/apibas/protocol`, not because its scenarios exist. gRPC, SOAP,
WebSocket and async remain UNSUPPORTED.

### What was built

- `protocol.GraphQL`: validates a JSON body with a `query` string and parses the query. The parser
  accepts field selections and arguments, and refuses fragments, aliases and malformed input before
  anything is sent. It reports selection depth, which the lab's fixed build uses.
- Lab route `POST /graphql` (`lab/graphql.go`). It resolves `order(id)`. The vulnerable build
  returns the full record to any authenticated caller (`LAB-GQL-RESOLVER-001`). The fixed build
  returns the public view to the owner only, and refuses queries deeper than 3 with 400.
- `contract.ProtocolSupported` now delegates to the adapter registry. There is one source of truth.

### Acceptance

- `protocol` unit tests: parsing, depth, malformed queries refused, body validation, registry.
- `TestPhase28_GraphQLINJ007VulnerableFailsFixedPasses`: vulnerable FAIL exploited, fixed PASS
  enforced.
- `TestPhase28_GraphQLABUSE004FixedEnforcesDepthLimit`: fixed PASS enforced. The vulnerable build is
  asserted to not be graded enforced.
- `TestPhase28_GraphQLCatalogBodiesValidate`: every GraphQL step body in the catalog passes the
  adapter, so a catalog entry cannot ship a body the adapter refuses.
- Tests that assumed GraphQL was unsupported now use gRPC, which still is (`phase15`, `phase27`,
  `phase28`, `coverage`). The count of unsupported protocols is now five scenarios, not seven.

### Measured result (complete, all 69 catalogued)

```
Catalogued:   69
Implemented:  64/69 (92.8%)
Evaluated:    64/69 (92.8%)
Validated:    63/69 (91.3%)
Exclusions (denominator still includes them):
  unsupported (no adapter):       5   (DISC-009 grpc, INJ-005 soap, AUTHN-011 websocket,
                                       ABUSE-010 async, INTEG-010 async)
  errored (execution/environment): 0
  unevaluated (implemented, no valid verdict): 0
```

64 + 5 = 69. The earlier measurement was truncated, so the validated count and the exclusion
breakdown could not be confirmed then. They are confirmed now.

### Gap found and recorded, not hidden

ABUSE-004 counts as **evaluated but not validated**. The fixed build PASSes (the deep query is refused
with 400). The vulnerable build accepts the deep query, but the grader has no depth oracle, so
nothing grades that acceptance as exploitation. The coverage rule counts a single valid verdict as
evaluated, so ABUSE-004 is in the 64, and it is not in the 63. A depth or node-count oracle is
needed before this scenario can prove it detects the flaw. Changing the grader is a separate
decision, so it is not made here.

### Decision applied: API-BAS-AUTHN-011

Kept under AUTHN as WebSocket handshake authentication. The objective is now exact: an
unauthenticated client on a foreign origin completes a handshake to the order event stream and
receives events. The expected control is a 403 refusal when the Origin is not allowed or no valid
bearer token is presented, with no event frame delivered. The "proposed" note is replaced by the
decision.

### Still open

- SOAP, gRPC, WebSocket and async adapters. Each needs its adapter, a lab route and acceptance tests
  before it is added to the registry.
- The depth oracle for ABUSE-004 (above).
- Protocol objectives for the four remaining entries (INJ-005, DISC-009, ABUSE-010, INTEG-010) are
  written, but their tests check only that they are unsupported. Their acceptance tests come with
  each adapter.


## Phase 30 - protocol adapter: SOAP (second of five)

- `protocol.SOAP` parses the request strictly. Entity declarations are read from the DOCTYPE first, and
  each external SYSTEM identifier must name a loopback lab host over http or https. Remote hosts,
  `file:` and `ftp:` are refused, so the adapter enforces the INJ-005 prerequisite.
- Lab route `POST /soap/orders` (`lab/soap.go`). The vulnerable build expands an external entity that
  names `.../internal/orders/{id}` to that internal record, protected values included
  (`LAB-INJ-XXE-001`). The fixed build refuses any document declaring an external entity with 400.
- Acceptance: parser and adapter unit tests (loopback accepted, remote/file/ftp refused, malformed and
  undeclared entities refused); `TestPhase28_SOAPINJ005VulnerableFailsFixedPasses` (FAIL exploited
  vulnerable, PASS enforced fixed); `TestPhase28_SOAPCatalogBodiesValidate`.
- Coverage: unsupported protocols now gRPC, WebSocket, async (4 scenarios); SOAP is implemented.


## Phase 31 - protocol adapter: gRPC, JSON transcoding form (third of five)

- Scope limit, stated plainly: this is gRPC-JSON transcoding over HTTP/1.1. A gRPC method is POSTed to
  `/{package.Service}/{Method}` with a JSON object body. It is not native gRPC framing over HTTP/2,
  because the runner's client speaks HTTP/1.1. Protobuf descriptors are not used. DISC-009's
  prerequisites say this.
- `protocol.GRPC` validates the JSON object body. `protocol.ValidateMethodPath` refuses any path that is
  not a method (the package may be empty).
- Lab route `POST /pkg.orders.v1.OrderService/GetOrder` (`lab/grpc.go`). The vulnerable build returns the
  full record to any caller (`LAB-DISC-GRPC-001`). The fixed build returns `PERMISSION_DENIED` as 403 to a
  non-owner.
- Acceptance: adapter unit tests (path shape, body shape, registration);
  `TestPhase28_GRPCDISC009VulnerableFailsFixedPasses` (FAIL exploited vulnerable, PASS enforced fixed);
  `TestPhase28_GRPCCatalogStepsValidate`.
- Unsupported now: WebSocket and async (3 scenarios).


## Phase 32 - protocol adapter: WebSocket handshake (fourth of five)

- Scope, decided in the review: API-BAS-AUTHN-011 stays under AUTHN as WebSocket handshake
  authentication. Objective: an unauthenticated client on a foreign origin completes a handshake and
  receives the order event. Expected control: 403 before the upgrade when the Origin is not allowed or no
  valid credential is presented, with no frame delivered.
- Grader change, stated plainly: the baseline of a WebSocket scenario is a successful handshake (101),
  not 200. The grader required 200, so every handshake scenario would have been skipped. A scenario now
  declares `baseline_status`. It defaults to 200 and may be 101 only for `protocol: websocket`. HTTP
  scenarios are unchanged.
- `protocol.WebSocket` validates the RFC 6455 opening handshake: GET, Upgrade, Connection token,
  Sec-WebSocket-Version 13, a 16-byte base64 key, and an Origin. It also refuses a handshake that carries
  a body.
- Lab route `GET /ws/orders` (`lab/websocket.go`). It performs a real handshake over a hijacked
  connection, with the RFC accept key, and sends one unmasked text frame carrying the order event, then
  closes. The vulnerable build accepts any Origin and any credential and streams the full record
  (`LAB-AUTHN-WS-001`). The fixed build requires the allowed Origin, a valid token and ownership, and
  refuses with 403 before the upgrade.
- The access-log wrapper now passes Hijack through to the connection and records 101.
- Acceptance: `TestWebSocketRefusesMalformedHandshake` and related unit tests;
  `TestPhase28_WebSocketAUTHN011VulnerableFailsFixedPasses` (FAIL exploited vulnerable, PASS enforced
  fixed); `TestPhase28_WebSocketCatalogHandshakesValidate`.
- Unsupported now: async only (2 scenarios: ABUSE-010, INTEG-010).


## Phase 33 - protocol adapters: async (fifth of five) and the GraphQL depth oracle

### Async (ABUSE-010, INTEG-010)

- `protocol.Async` validates a publish: a JSON object with an `event` name, a publish path, and, where
  present, the `X-Event-Signature` shape (`sha256=` and 64 lowercase hex).
- Lab broker `POST /broker/topics/{topic}/publish` (`lab/broker.go`), two topics with separate policies:
  - `orders.events` requires a valid HMAC-SHA256 signature over the body. The vulnerable build does not
    verify it (`LAB-INTEG-EVENT-001`), so an altered event is processed and changes the order's status.
    INTEG-010's attack re-sends the created event's signature over a cancelled event for the same
    order. The fixed build refuses it with 403.
  - `orders.retries` needs no signature. Each publisher gets five accepted publishes per topic in the
    fixed build, then 429. The vulnerable build has no limit (`LAB-ABUSE-QUEUE-001`). ABUSE-010 now
    publishes to this topic. Its unsigned baseline would otherwise be refused by the signed topic.
- Disclosure on the signing key: the lab's HMAC key is `audspect-lab-event-key-v1`, a fixture constant in
  the lab code. It is not a production secret. The scenario embeds the baseline signature value for its
  own body, never the key. The INTEG-010 prerequisites say this.
- The adapter `ValidatePublishPath`, `ValidateSignatureHeader` and body checks run in the catalog test
  against each step, with `{n}` substituted as the runner does.

### GraphQL depth oracle (ABUSE-004) and a grader addition

- The grader's existing items oracle reads only a top-level `items` array, which a GraphQL response does
  not have, so it could not grade this scenario. Rather than bend it, a general oracle was added:
  `max_response_depth` in the contract. An attack response whose JSON nests deeper than the declared
  depth counts as an oversized grant, which is FAIL exploited. A response of nested objects and arrays
  is measured by `jsonDepth`. Non-JSON responses are never counted as deep.
- The lab's `order` now has an `items` relation. Each item points back to its order, so a selection
  nests the response as deep as the query does. The vulnerable build resolves it without a limit. The
  fixed build refuses queries deeper than 3 with 400 before any resolver runs.
- ABUSE-004 is now FAIL exploited vulnerable and PASS enforced fixed, so it is validated. Phase 29 had it
  as evaluated only. That gap is closed.

### Acceptance (all five protocols)

- Async: `TestPhase28_AsyncABUSE010VulnerableFailsFixedPasses`,
  `TestPhase28_AsyncINTEG010VulnerableFailsFixedPasses`, `TestPhase28_AsyncCatalogStepsValidate`, and
  adapter unit tests in `protocol/async_test.go`.
- GraphQL: INJ-007 and ABUSE-004 both graded as in Phase 29.
- Every protocol now has an adapter, so no catalogued scenario is UNSUPPORTED. The zero-traffic
  guarantee is tested with protocol names that have no adapter (`quic`, `mqtt`), so the gate still
  holds for any future protocol.

### Measured result (all 69 catalogued, lab against lab)

Two complete runs of the same code gave different validated counts, 67 and 68. The difference was one
scenario, ABUSE-002 (timing-based), which is validated in some runs and not in others. This is the
pre-existing timing flake already noted (its calibration is not hardware-robust). It is not caused by
the protocol work, and this phase does not change its timing logic.

```
Catalogued:   69
Implemented:  69/69 (100.0%)
Evaluated:    69/69 (100.0%)
Validated:    68/69 (98.6%) in the last run; 67/69 in the earlier one
Exclusions: unsupported 0, errored 0, unevaluated 0
Not validated: ABUSE-002 (timing flake, intermittent)
```

### What "supported" means here, and its limits

A protocol is supported only when its adapter is registered and its lab route and acceptance tests exist.
Each limit is stated where it applies:

- gRPC is JSON transcoding over HTTP/1.1, not native gRPC over HTTP/2.
- WebSocket covers the opening handshake and one server text frame, which the runner reads as raw bytes.
  It does not implement a frame parser or client masking.
- SOAP covers the XML external-entity case the scenario tests. It is not a WSDL or a full SOAP stack.
- Async is a single lab broker with two topics. It is not a real message broker.

### Still open

- ABUSE-002 timing flake (pre-existing; needs a calibration decision, not a code fix here).
- The Windows `build.ps1` run and the staging item for ABUSE-002, as in earlier phases.


## Phase 34 - detection (Phase 4): first slice, Elastic-style fixture

### SIEM decision

The primary emulated SIEM is **Elastic Security**: its rule set and event fields already exist in
`internal/apibas/detect`, so the fixture rules are modelled on it. The Sentinel fixture stays as a
parity check. No scenario uses it yet. Both are fixtures, and every result is labelled not validated
against a live SIEM. Neither has been run against a live product.

### What changed

- **Coverage of the REL-004 rule.** 25 cross-identity scenarios gained a detection block that expects
  `APIBAS-REL-004` (access to an object owned by another identity), with `min_severity: high`. Their
  `detection_assertion` moved from `not_evaluated` to `fixture_validated`. AUTHZ-001 already had one.
  ABUSE-001 already had a block (REL-001). In total 27 scenarios are fixture-validated and 42 remain
  `not_evaluated`, each for a reason given below.
- **Vocabulary.** The fixture returned `missed`. The blueprint defines `not_detected`, so the fixture
  now returns `not_detected`.
- **Owner attribution (lab).** The lab attributed an owner only from `/api/orders/{id}` paths. It now
  attributes from any path segment that names an order, and from decoded query values. Before this,
  INJ-008's traversal parameter, which names ORD-2001, was invisible to the rule.
- **Expectation derived from the fixture, not a pattern.** `TestPhase34_DetectionMatchesFixtureOwnership`
  computes each expected result from the fixture's ownership and the attacker's identity, before the
  run. A detection is expected when the request names an object owned by someone other than the
  attacker. The test covers both builds, and it passes.

### Two findings the expectation encodes

- **Forged identity headers blind the SIEM in the vulnerable build.** AUTHN-008 (`X-Customer-Id`) and
  GWAY-001 (`X-Gateway-Identity`) are not detected in the vulnerable build, because the vulnerable product
  accepts the forged header and the access log records the claimed identity as the caller. The fixed build
  ignores the header and is detected. This is a real blind spot: a SIEM that records the identity the
  product accepted cannot see identity forgery. The expectation models it and is not changed to hide it.
- **Body-carried object IDs are outside the rule's view.** GraphQL, SOAP, gRPC and WebSocket scenarios
  name the object in the request body, which the access log does not record. These are expected
  `not_detected`. Closing that gap needs the SIEM to see request bodies, which is a design decision.

### What is not done

- 42 scenarios remain `not_evaluated`. Most are property-level or function-level attacks (injection with
  no object reference, counted-request abuse, header checks). REL-001 to REL-004 do not describe them.
  Detecting them needs new rules that the event model can support, such as a rule on repeated throttled
  requests from one identity, or on server faults. Each needs its own expectation before it is added.
- DET-009 (delayed telemetry, `inconclusive` outside the window) is not built. The fixture has no delay
  injection.
- ABUSE-002 is still intermittent (pre-existing, timing-based).

### Measured result after this change (lab against lab)

```
Catalogued:   69
Implemented:  69/69
Evaluated:    69/69
Validated:    69/69 (this run; ABUSE-002 is intermittent, see Phase 33)
```

Exploitability and control verdicts are unchanged by the detection work.


## Phase 35: ABUSE-002 stability, dedicated detection rules, telemetry states

Exploitability and detection are reported separately below. The 69/69 validated figure is the exploitability
metric. It is not detection coverage.

### Exploitability validation (unchanged metric)

```
Catalogued:   69
Implemented:  69/69
Evaluated:    69/69
Validated:    69/69 (vulnerable FAIL exploited, fixed PASS enforced)
Exclusions:   unsupported 0, errored 0, unevaluated 0
```

### Detection validation (separate metric)

```
vulnerable  detected=14  not_detected=16  inconclusive=0  error=0
fixed       detected=16  not_detected=14  inconclusive=0  error=0
not_evaluated (no detection block) = 39 of 69 scenarios
```

Thirty scenarios declare a detection block. This does not mean comprehensive detection coverage. The
`not_detected` results are real: they are misses, and most of them are the recorded findings below.

### ABUSE-002 timing flake: root cause and fix

- **Root cause.** The latency grader applied the attack-spread gate to every verdict. A PASS on a sub-millisecond
  request could be pushed to inconclusive by one scheduler outlier, because the outlier raised the CV. A PASS
  does not rest on spread: it needs every round under the ceiling. Only a FAIL rests on the ratio, so only a FAIL
  needs a stable attack spread.
- **Fix.** The baseline-variance gate applies to every verdict, because the environment check depends on it. The
  attack-spread gate moved into the FAIL (crossed) path only.
- **Deterministic tests** (`latency/flake_test.go`): sub-millisecond PASS survives an outlier; stable crossing is
  FAIL; unstable crossing is inconclusive; unstable baseline gates a PASS. All four pass.
- **Repeatability** (`runner/abuse002_test.go`, five runs per build, verdicts stated before the run). Vulnerable:
  FAIL/exploited on 5 of 5. Fixed: PASS/not_exploited on 5 of 5. The earlier fixed-build flake was 2 of 5 runs
  with EXCESSIVE_VARIANCE. It is now stated as five clean runs, not as proof.

### Dedicated detection rules (REL-001 to REL-004 unchanged)

- `APIBAS-REL-005` counted-request burst: ten or more requests in one run.
- `APIBAS-REL-006` injection-shaped request: an injection class in the request target, or in the body when
  body extraction is on. The event carries class names only, never the matched text.
- `APIBAS-REL-007` privileged function invoked (delete order, read audit, rotate key, change key status).
- `APIBAS-REL-008` sensitive projection (statement, card, audit, view) of an object owned by another identity.

Each rule has an expectation written in `runner/phase34_detection_test.go` from the rule's definition and the
scenario's payload, before any run. The table test runs every declared scenario in both builds, with body
extraction off and on, twice each. Result: 30 of 30 scenarios match their expectations on both passes.

### Body-identifier extraction: privacy control

- Off by default (`lab.Config.ExtractBodyIDs`). With it off, no request body is read.
- When on, the lab reads at most 64 KiB, keeps the owner of a known order whose ID appears in the body, and
  keeps injection class names. The body is discarded and is never logged or stored on an event.

### Telemetry states (DET-009 equivalent, AUTHZ-001)

No catalogued DET-009 scenario exists. The telemetry states are tested on AUTHZ-001 instead.

| Telemetry | Window | Expected detection | Observed |
|---|---|---|---|
| normal | default | detected | as expected |
| missing (`telemetry-missing`) | default | inconclusive, reason "telemetry incomplete" | as expected |
| delayed beyond window (`telemetry-delayed`, 3s) | 1s | inconclusive | as expected |
| delayed inside window | 6s | detected | as expected |

Exploitability is identical in all four cases. Telemetry changes only the detection axis.

### Findings (kept, not hidden)

- **Forged identity headers are a blind spot in the vulnerable build.** The access log records the identity the
  product accepted. A forged `X-Customer-Id` or `X-Gateway-Identity` makes the request look like the claimed
  identity's own access. The expectation models this, and it is not changed to pass.
- **AUTHZ-007 body names two owners; the lab keeps one.** The body names `ORD-1001` (owned by the attacker,
  `cust-a`) before `ORD-2001` (owned by `cust-b`). The lab keeps the first named owner only, so the foreign object
  is dropped and the event is attributed to the attacker's own order. The rule's definition expects `detected`
  with extraction on. The observed result is `not_detected`. It is recorded as a named finding
  (`knownAttributionGap`), and the test fails if the observation changes. Decision needed: have the event carry
  every named owner (changes the event contract), or narrow the scenario's claim.
- **Catalog claim to revisit.** AUTHZ-007 is still `fixture_validated` in the catalog. That overstates the
  extraction-on case. It should be narrowed or the gap closed before it counts as validated.

### Not done

- 39 scenarios remain `not_evaluated` (no detection block). Detection coverage is not claimed for them.
- The repeatability gate is applied per test run (two consecutive passes). It is not yet a standing gate on every
  scenario's catalog status.
- Windows `build.ps1` run and the staging ABUSE-002 item remain carry-overs.
