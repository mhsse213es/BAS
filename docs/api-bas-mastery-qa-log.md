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
