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


## Phase 35 addendum: AUTHZ-007 status narrowed, multiple-owner event contract

### Decisions applied

- **AUTHZ-007 was narrowed, then restored.** While the gap was open, its detection assertion was `not_evaluated` and
  its detection block was removed, because the contract allows `not_evaluated` only without a block. Once the gap was
  closed and both configurations passed, it returned to `fixture_validated`. The reason states both configurations.
- **Event-contract change (explicit).** Access events now carry `object_owners`: every distinct owner the path, the
  decoded query and (with extraction on) the body name, in that order. `object_owner` stays as the first owner, so it
  equals `object_owners[0]`. Owners are the lab's own identifiers, never request text.
- **Bounds and validation.** Both the lab and `detect.Event.Validate` cap owners at 16 and reject empty owners and a
  mismatched `object_owner`.
- **Downstream impact checked before the change.** Consumers of the owner field were all inside
  `orchestrator/internal/apibas`: REL-004 and REL-008 (now read every owner), the Sentinel mapping (single owner
  column), the admin client (decodes by JSON tag) and the lab. No consumer outside the package reads it.
- **Sentinel limit recorded.** `ToSentinelRecord` writes only the first owner, because Sentinel's record has one owner
  column. No scenario routes through Sentinel, so this has no effect on current results.
- **Privacy unchanged.** Extraction is still off by default, and only owner identifiers and injection class names are
  kept. No matched text is stored.

### Verification

- Unit tests (`detect/owners_contract_test.go`): a second foreign owner counts as foreign; single-owner meaning is
  unchanged; a mismatched `object_owner` is refused.
- Regression (`runner/authz007_test.go`): extraction off gives not_detected, extraction on gives detected, in both
  builds, with exploitability unchanged.
- Table (`TestPhase34_DetectionMatchesDeclaredExpectations`): 30 of 30 declared scenarios match on two consecutive
  passes, in both builds, with extraction off and on.
- Measured run: exploitability 69/69 validated. Detection (extraction off, the measured configuration): vulnerable
  14 detected / 16 not detected; fixed 16 / 14; 39 of 69 not evaluated. These counts are unchanged, as expected:
  the measured run does not enable extraction.

### Still open

- **DET-009 is not defined.** The telemetry states were tested on AUTHZ-001. A DET-009 scenario still has to be
  defined in the catalog with its own expectation and tested.
- 39 scenarios remain not evaluated. Detection coverage is not claimed for them.
- Repeatability is checked per test run (two consecutive passes), not as a standing catalog gate.
- Five runs on this machine do not prove stability across machines or workloads.
- Windows `build.ps1` run and the staging ABUSE-002 item remain carry-overs.


## Phase 35 addendum 2: API-BAS-DET-009 (telemetry delay)

Blueprint DET-009: detection holds when telemetry is delayed or partly missing.

### Scenario

- `API-BAS-DET-009` (`catalog/API-BAS-DET-009.yaml`), category DET, claim cross_identity. The attack is the
  AUTHZ-001 cross-identity read, so exploitability is the same. Its precondition is `lab_faults: [telemetry-delayed]`.
- The lab holds each access event for 3 seconds. The runner's default detection window is 2 seconds, so at the
  default window the rule cannot see the attack event in time.

### Expectations (written before the run)

| Configuration | Window | Expected detection |
|---|---|---|
| declared: telemetry-delayed | default (2s) | inconclusive, reason "telemetry incomplete" |
| telemetry-delayed | 6s | detected |
| telemetry-delayed + telemetry-missing | default | inconclusive |
| no delay fault | default | the run is SKIPPED (precondition); detection not_evaluated |

### Result

- The declared configuration grades `inconclusive`, never `not_detected`. The blueprint requirement that detection
  holds under delay is **not met at the default window**. The scenario records this as the observed result. It is
  not a pass.
- Detection holds only when the window covers the hold, and the 6s configuration shows that. Whether a production SIEM
  window covers real delays is a deployment question this fixture does not answer.
- The DET-009 table entry is `fixture_validated` for the stated expectation, which is repeatable across two passes in
  both builds (`TestPhase34_DetectionMatchesDeclaredExpectations`, `TestDET009DetectionUnderTelemetryStates`).

### Defect found and fixed while testing DET-009

- **Skipped runs were graded `not_detected`.** The runner refuses a scenario whose required lab fault is absent, and
  returns a SKIPPED report with no traffic. The detection stage still ran and treated zero events as a miss. That counts
  an unexecuted scenario as a false negative.
- **Fix.** A run that is SKIPPED or ERROR, or has no exchanges, now gets detection `not_evaluated` with a reason
  naming the outcome. `detect.NotEvaluated` is distinct from `NotDetected`.
- **Impact on earlier numbers.** None. Every scenario declaring a detection block executed in earlier measured runs,
  so no recorded count changes.

### Counts after this addendum

```
Catalogued:    70
Exploitability: 70/70 validated
Detection declared: 31 (vulnerable: detected 14, not_detected 16, inconclusive 1;
                        fixed: detected 16, not_detected 14, inconclusive 1)
Not evaluated (no detection block): 39 of 70
```

### Still open

- Detection coverage is not claimed for the 39 not-evaluated scenarios.
- DET-009's window result depends on the fixture's 2s window, not on any production SIEM setting.
- Repeatability is per test run, not a standing catalog gate.
- AUTHZ-007 is `fixture_validated` on `main` (commit a89ccc96). Its reason states both configurations and the
  multiple-owner contract. The earlier recommendation to narrow it is superseded unless you ask for that change.


## Phase 36: item-count pagination (ABUSE-003)

### Open item closed

- The earlier record said the item-count check needed a fixture with more records than the cap. That is now
  met. `orders-paged` gives customer-b 151 owned orders (ORD-2001 and ORD-P001..P150), and the page cap is 100.
  The earlier "fixture has two orders" limitation is superseded for this check.
- The check is the item count of the `items` array, graded by `max_items_returned: 100`.

### What changed

- **Oversize checks extracted.** The four bounds (granted page size, accepted bytes, item count, response depth)
  moved from the grader loop into `oversizedHits`. Each bound counts once and independently.
- **Isolation.** The earlier ABUSE-003 test could fail on the page size alone, because its attack also requests
  `limit=100000`. Two tests now isolate the item-count path:
  - `TestOversizedHitsItemCountAlone` (unit): an item count over the cap alone is one hit; an item count at the cap
    is none; a refused request is none; both bounds exceeded give two.
  - `TestPhase12_ItemCountFromLab` (lab): the vulnerable build returns all 151 items for `limit=100000`; the fixed
    build refuses that limit with 400; the fixed build returns exactly 100 items for `limit=100`.

### Limit of this evidence

- The report keeps only the first 2 KiB of each body, so item counts are checked against the lab directly, not from
  the report.
- Only ABUSE-003 uses this fixture. Other pagination-adjacent scenarios (DATA-004 bulk enumeration) are not
  re-graded here.


## Phase 37: ABUSE-006 (expensive downstream validation) and ABUSE-007 (paid SMS consumption)

These two were the last unbuilt sub-techniques. Both are now built and pass in both builds.

### Built

- **ABUSE-006** `POST /api/validate/order-lines`. Each accepted request calls the downstream validator. The
  vulnerable build has no limit (LAB-ABUSE-VALIDATE-001). The fixed build allows 5 per run and caller, then 429
  before any downstream call.
- **ABUSE-007** `POST /api/auth/otp/send`. Each accepted request sends a paid SMS. The vulnerable build has no
  limit (LAB-ABUSE-OTP-001). The fixed build allows 3 per run and caller, then 429.
- Both use the accepted-attempts oracle (`max_accepted_attempts`, 5 and 3). The earlier ABUSE-008 pattern.

### Boundary: what "second service" means here

- The downstream validator and the SMS provider are in-process boundaries with per-run counters. They are not
  separate listeners. The tests show that the product's request triggers the downstream work. They do not test
  network-level behaviour between services, timeouts, or retries across a real network hop.

### Evidence

- `TestPhase37_ExpensiveAndPaidAbuse` counts the accepted and refused responses in the report, so the downstream
  or paid work is observed rather than inferred from the verdict. Vulnerable: 10 of 10 accepted for both. Fixed:
  5 accepted and 5 refused (ABUSE-006); 3 accepted and 7 refused (ABUSE-007).
- The flaw registry links both flaws to their catalog IDs (`TestFlawRegistryLinksToCatalog`).

### Measured after this phase

```
Catalogued:    72
Implemented:   72/72
Evaluated:     72/72
Validated:     72/72  (exploitability)
Detection:     31 declared (unchanged). Not evaluated: 41 of 72.
```

The 41 not-evaluated count includes ABUSE-006 and ABUSE-007, which have no detection block. No detection coverage is
claimed for them.

### Still open

- Network-level service behaviour (separate listeners) is not tested. The boundaries are in-process.
- The two scenarios make no detection claim.

## Open items for QA (owner: user)

### Timing qualification gate

- **Item:** Once a controlled staging machine is qualified (documented configuration, recorded fingerprint and load,
  qualified calibration record, approved threshold), run five repeat runs per build for each timing scenario. Require
  identical verdicts on every run before making any timing-based validation claim.
- **Blocked on:** (1) a named product or security requirement owner approving the ceiling (ABUSE-002's 250 ms is
  provisional); (2) a controlled staging machine. Until both are resolved, do not start new timing scenarios or claim
  timing validation.
- **Current state:** ABUSE-002 carries `timing_claim: provisional`. It is evaluated but not validated. The developer
  workstation's five stable runs are diagnostic evidence only.
- **Source:** `docs/api-bas-timing-policy.md` (decisions recorded, execution status).

### Production gaps (owner: user to decide, engineering to build)

- **Result persistence.** API BAS run results are written to stdout only (`cmd/apibas-runner`). Nothing stores
  them. Decision needed: database and schema. Default assumed: the orchestrator's existing Postgres, with a
  migration.
- **Scheduling.** Nothing in the orchestrator runs API BAS. The `internal/jobs` package has no API BAS references.
  Decision needed: reuse `internal/jobs`, or add a new trigger.
- **Production secret store.** `runner.MapSecrets` is for tests and the local lab only. `apibas-runner` reads
  credentials from environment variables. Decision needed: which secret store backs production. The adapter sits
  behind the existing `SecretResolver` interface.

## Phase 38: result persistence (open item 1 of production gaps)

### Built

- `internal/db/apibas_schema.go`: `apibas_runs`, one row per scenario run per build (`UNIQUE (run_tag, build)`), with
  the full report as `jsonb`. Outcome columns are copied out so they can be queried without parsing the report.
- `internal/db/apibas_store.go`: `SaveAPIBASRun` validates the record (build, result, JSON) before it reaches the
  database, and refuses a second save of the same tag and build. `ListAPIBASRuns` lists a scenario's runs newest first.
- `cmd/apibas-runner`: optional persistence. Set `APIBAS_DB_DSN` and `-build vulnerable|fixed`. The DSN comes from the
  environment, so the password never appears on the command line. JSON output to stdout is unchanged.

### Tests

- `TestAPIBASRunSchemaIdempotent`, `TestAPIBASRunSaveAndList`, `TestAPIBASRunDuplicateTagAndBuildRefused`,
  `TestAPIBASRunInvalidInputRefused`. All pass against the Docker test database.
- End to end: the vulnerable lab and `apibas-runner` ran `API-BAS-AUTHZ-001` with persistence on. The stored row matched
  the stdout outcome (FAIL, exploited, detected). The stored report contains no credential values. The only match for
  credential-like text is the field name `webhook_secret`, whose value is `[REDACTED]`.

### Open items remaining

- **Scheduling.** Not built. Nothing in the orchestrator triggers API BAS runs. `internal/jobs` has no API BAS references.
- **Production secret store.** Not built. `apibas-runner` still reads credentials from environment variables.
- **Database choice.** Persistence uses the orchestrator's existing Postgres (`pgxpool`, `EnsureSchema`-style
  idempotent creation). That was the stated default, and it needs confirming.
- Results are not yet visible in any UI or API. Reads are only through `ListAPIBASRuns`.

## Phase 39: read-only results API (implementation order step 1)

### Built

- `GET /api/apibas/runs` (optional `scenario`, `limit` 1 to 500, newest first) and
  `GET /api/apibas/runs/{id}` (verdicts, detection outcome and reason, timing verdict, detail, evidence references).
- Authorization: `auth.CanViewAPIBASRuns` (`apibas:runs:view`), granted to Admin and Analyst. Viewer and unauthenticated
  requests get 403. Installations are separate databases, so the permission is the authorization boundary. No tenant
  column is needed, and none was added.
- The detail view returns evidence references, one per stored exchange, as `<run_tag>#<index>` with step, method, path,
  status and redacted-leak count. **Response bodies are not returned.** Exposing bodies is a separate decision.
- The RBAC matrix (`rbac_matrix_test.go`) lists both routes, and the drift test passes.

### Tests

- Authorization matrix: no identity and Viewer get 403; Analyst and Admin get 200.
- Invalid `limit` gets 400; unknown run gets 404.
- Detail lists two evidence references for a two-exchange run, with the leaked-value count.
- A planted body value does not appear in any list or detail response.
- `TestRBACMatrix_NoDrift`, `go build ./...`, and the API BAS and auth short suites pass.

### Still open (implementation order steps 2 to 4)

- **Step 2, orchestrator integration.** Scheduling and dispatch are not built. Trigger, authorization for triggering,
  cancellation, timeouts, concurrency limits, and failure handling are all undecided. Lifecycle transitions are not persisted.
- **Step 3, production secrets.** Not built. Environment variables are still the only source.
- **Step 4, end-to-end tests.** The scheduled-execution, timeout, cancellation and secret-redaction tests depend on steps 2
  and 3 and are not written.
- The results API has no UI. Its list is capped at 500 rows, with no paging cursor yet.


## Blueprint Phase 2: core security vectors (acceptance)

Scope is the 58 P2 IDs from the blueprint's phase column (not the text list). All 58 are catalogued.

Correction: an earlier note listed DISC-006 as Phase 2 scope. The blueprint table marks it P3, so it is not Phase 2.

### Evidence

- `TestPhase2_ScopeAcceptance` (commit `d97bf19b`, on main). Every P2 scenario gives FAIL/exploited on the
  vulnerable build and PASS/enforced on the fixed build. Passed in one run, about 82 s.
- Fixture missing gives SKIPPED and is not counted. Covered by `TestPhase2_MissingRevokedCredentialIsPreconditionSkip`
  and `TestMissingCredential_IsPreconditionSkip`.
- Injection, "payload blocked" versus "exploit proven": the outcome separates FAIL/exploited from PASS/enforced. It
  does not record whether a blocked payload was refused (denied status) or accepted without harm. Both are
  enforced. Recorded as a limit of the outcome model, not a failure of the criterion as written.

**Phase 2 status: closed** on the criteria above.

## Blueprint Phase 3: business logic (in progress, not closed)

### Built

- BIZ-001, 003, 004, 005, 006, 007, 008, 009, 010, 011 (10 of the 10 BIZ P3 scenarios; BIZ-012 is P4). Lab routes
  in `lab/biz.go`; flaws LAB-BIZ-*; catalog entries in `catalog/`.
- Batch 1: AUTHN-010 (step-up for a sensitive action) and DATA-007 (export carries protected fields). Routes in
  `lab/batch1.go`; flaws LAB-AUTHN-STEPUP-001 and LAB-DATA-EXPORT-001.
- Engine: the contract has a `parallel` field for repeated attack steps. The runner sends the repeats concurrently
  and folds results in send order. When the race mixes accepts and refusals, the reported status is the refusal,
  because which concurrent request wins is not fixed.
- State adapter: `StateRecord` carries `BeneficiaryRef`, so BIZ-009's change is visible to the state oracle.

### Defects found while building, fixed

- Vulnerable withdrawal wrote to a nil counter map and panicked; the lab returned errors and the grader reported
  TARGET_UNREACHABLE. Fixed with `bizBump`, which creates the map on first use.
- Parallel aggregate status took the last accept in send order, which is not deterministic. BIZ-005 fixed build
  graded SKIPPED/EVIDENCE_INCONCLUSIVE on that ordering. Fixed as above.

### Evidence

- `TestPhase3_BIZScopeAcceptance`: 10 of 10 pass in both builds. Run 20 times in one process: 20 of 20 pass.
  The race window is 100 ms on this machine. Repeatability on the qualified timing machine is not claimed.
- `TestPhase3_Batch1Acceptance`: 2 of 2 pass in both builds, three consecutive runs.
- `TestFlawRegistryLinksToCatalog`, `TestTimingClaimRules` and the Phase 2 scope test pass with 84 catalog entries.
- Full `internal/apibas/runner` package (non-short, detection and ABUSE-002 suites included): passed, exit 0, about
  470 s. That run was compiled before batch 1, so batch 1 is covered only by its own test and the short suite.

### Still open (blueprint P3, 16 of 18 remaining)

- Not built: AUTHN-004, 005, 009; DATA-005, 009, 010; DISC-006, 010; INTEG-001, 002, 006, 007, 009, 011.
- Blocked: AUTHN-007 (client-certificate validation) and GWAY-012 (TLS and upstream trust). The lab has no TLS
  listener. Both need one before they can be built honestly.
- P3 scenarios already in the catalog before this phase (ABUSE-004, 006, 007, 010; AUTHZ-012; DISC-009; INJ-005,
  007; INTEG-005, 010; BIZ-002) were not re-run under a Phase 3 acceptance test. They run in the catalog-wide tests.
- The blueprint's replay acceptance for webhooks needs INTEG-002, which is not built.
- BIZ and batch 1 make no timing claim and no detection claim (`detection_assertion: not_evaluated`).


## Blueprint Phase 3, batch 2: AUTHN-004, 005, 009 and DATA-005, 009, 010

### Built

- AUTHN-004: the authorize endpoint accepts any redirect URI in the vulnerable build (LAB-AUTHN-REDIRECT-001). The
  fixed build requires the registered URI and a PKCE challenge. Graded by a forbidden `Location` header.
- AUTHN-005: the token endpoint exchanges a code without the PKCE verifier and accepts a reused code in the
  vulnerable build (LAB-AUTHN-PKCE-001). The fixed build checks the verifier and consumes the code. Graded by the
  accepted-attempts oracle (2 exchanges, maximum 1).
- AUTHN-009: the service-token endpoint issues a workload token without the client secret in the vulnerable build
  (LAB-AUTHN-SVC-001). Graded by the accepted-attempts oracle (2 requests, maximum 1).
- DATA-005: a filter on a protected field returns other tenants' protected values in the vulnerable build
  (LAB-DATA-FILTER-001). The fixed build refuses non-public filters with 400.
- DATA-009: a staging route returns protected values to customers in the vulnerable build (LAB-DATA-STAGING-001).
  The fixed build returns 404.
- DATA-010: the file endpoint accepts a signature issued for the caller's own file on any key in the vulnerable
  build (LAB-DATA-SIGNEDURL-001). The fixed build binds the signature to its key and checks the owner.

### Two modelling choices, and a grader limit they expose

- **The leak oracle is scoped to the precondition object.** `runner.go` counts a leak only when a response contains
  a protected value of the scenario's precondition object. A leak of any other object is not graded. DATA-005 and
  DATA-010 first named the attacker's own object, which made them miss the cross-tenant leak. The scenarios now
  name the other tenant's object (ORD-1001) and model two identities: customer-a owns it and reads it in the
  baseline, customer-b attacks. Both are `function_level` because the property-level rule requires the attacker to
  own the object.
- **The grader cannot see a cross-tenant leak of an object that is not the precondition object.** This also affects
  any other scenario whose attacker reads a third party's data. Widening the oracle to every fixture object would
  change verdicts across the catalog, so it is not done here. It needs its own review before a change.

### Other notes

- AUTHN-004, DATA-005, DATA-009 and DATA-010 are `READ_ONLY`, because the contract requires a mutating step for
  `STATE_CHANGE_SANDBOX`. AUTHN-004's authorize step records an issued code in the lab's bookkeeping. That record is
  not graded, so `READ_ONLY` is accurate for the oracle, not for the lab internals.
- DATA-005's inference side channel (a count or an existence check) is not graded. The scenario grades a direct
  protected-value disclosure through the filter. Pure inference is not claimed.

### Evidence

- `TestPhase3_Batch2Acceptance`: 6 of 6 pass in both builds, three consecutive runs.
- `TestPhase3_BIZScopeAcceptance`, `TestPhase3_Batch1Acceptance`, the Phase 2 scope test, the flaw-registry test and
  the timing-claim rules pass with 90 catalog entries.
- Short `internal/apibas/...` suite: clean.
- Full `internal/apibas/runner` package (non-short, detection and ABUSE-002 suites included): passed, exit 0, about 610 s.

### Still open (blueprint P3)

- Ten P3 scenarios remain: eight buildable in the HTTP lab (INTEG-001, 002, 006, 007, 009, 011; DISC-006, 010) and
  two blocked (AUTHN-007 client-certificate validation and GWAY-012 TLS). The lab has no TLS listener.
- DATA-005 and DATA-010 cross-tenant grading depends on the precondition-object scope above.


## Grader: forbidden values across tenants (closes the batch 2 leak-scope limit)

### What changed

- A scenario may declare `forbidden_values`: exact values that must not appear in an attack response. Each is
  searched at any depth of a JSON body, in keys and in strings and numbers, so nested arrays and JSON escapes are
  covered. A non-JSON body is searched as text.
- Any hit is `FAIL / exploited`, whatever the status.
- A response that cannot be fully searched (compressed body, invalid UTF-8) is `SKIPPED / EVIDENCE_INCONCLUSIVE`. It
  never passes. The grader has no separate INCONCLUSIVE result, so this is the existing inconclusive outcome.
- A forbidden value that the attacker also sent (in the path, query or body) is not counted. The product echoing the
  attacker's own input is not a disclosure. Scenarios therefore pick values the attacker did not send.
- `forbidden_values` entries must be at least 4 characters. Shorter values are rejected by the contract.
- The existing precondition-object leak check is unchanged and still runs.

### Limits, as stated in the design

- Only exact, distinctive values are caught. Masked, hashed, base64-encoded or partly redacted data is not.
- Only the attack response is searched. A leak in a later read is not caught.
- Common values give false positives. Scenario authors choose values that belong to another identity.

### Used by

- DATA-005: forbidden `BAS-SIM-1001` and `BAS-SIM-WHSEC-1001`, the other tenant's card and webhook reference. The
  attacker's filter value `BAS-SIM-ACC-A` is sent, so it is deliberately not a forbidden value.
- DATA-010: forbidden `BAS-SIM-ACC-A` and `BAS-SIM-1001`, the other tenant's account and card reference.
- DATA-005 and DATA-010 are back to single-identity scenarios on the attacker's own object. The two-identity
  modelling from batch 2 is no longer needed.

### Evidence

- Regression tests (`runner/forbidden_test.go`): foreign ID at top level, nested in an array, absent. Also JSON
  escapes, key names, non-JSON text, echoed request values, compressed body, invalid UTF-8, no values declared.
- Grader tests (`grade/forbidden_test.go`): hit is FAIL/exploited; uninspectable never passes; hit outranks
  uninspectable; denied and inspectable still passes.
- `TestPhase3_Batch2Acceptance`, `TestPhase3_BIZScopeAcceptance`, `TestPhase3_Batch1Acceptance` and
  `TestPhase2_ScopeAcceptance` pass. The short suite is clean.
- For DATA-005 the filter matches only the other tenant's order, so the FAIL cannot come from the precondition
  check. It comes from the forbidden value.


## Blueprint Phase 3, batch 3: the eight HTTP-buildable remaining scenarios

### Built (lab routes in `lab/batch3.go`, flaws LAB-INTEG-* and LAB-DISC-*)

- INTEG-001: a partner quote returns a quantity outside its contract. The vulnerable build applies it. The fixed
  build refuses it with 422.
- INTEG-002: a signed webhook event is replayed. Both builds verify the signature. The fixed build accepts an event ID
  once per run and refuses the replay with 409. The signature does not bind a timestamp freshness window, which
  is not graded here (see limits).
- INTEG-006: a proxy acts as the identity named in X-Act-As. The fixed build refuses acting as another identity (403).
- INTEG-007: the fraud check is down (`fraud-check-down`, a lab fault). The vulnerable build authorizes the payment
  (fails open). The fixed build fails closed with 424.
- INTEG-009: a partner names a customer it is not authorized for. The fixed build allows only cust-b (403).
  The partner credential is sent in its own `X-Partner-Token` header, so the customer's Bearer token does not replace it.
- INTEG-011: a callback URL on a host outside the allowlist. Graded by the accepted-attempts oracle (2 attempts, maximum 1).
- DISC-006: the staging environment (`X-Environment: staging`) skips authentication in the vulnerable build. The
  fixed build requires it (401).
- DISC-010: the legacy region (`X-Region: legacy-eu`) skips the owner check in the vulnerable build. The fixed build
  returns 404 for another tenant's order in every region.

### Two grader rules that shaped the design

- The runner takes the baseline identity as the object owner for every claim type, so a baseline step must be
  authenticated as that owner. An anonymous attack step is allowed.
- A step with `auth: none` must name the `anonymous` identity (contract rule).

### Limits

- INTEG-002 does not check timestamp freshness. A replay inside the same run is graded. A delivery that is old but
  first-seen is not. The freshness window is not part of this scenario.
- INTEG-007 tests the behaviour when the fraud check is down. The attacker does not cause the outage. The lab fault
  stands for the outage.
- The partner-credential and environment and region headers are lab conventions. They are not a real gateway.

### Evidence

- `TestPhase3_Batch3Acceptance`: 8 of 8 pass in both builds, three consecutive runs.
- The Phase 2 scope test, the earlier Phase 3 tests, the flaw-registry test and the timing-claim rules pass with
  98 catalog entries. The short suite is clean.
- Full `internal/apibas/runner` package: one failure, `TestABUSE002Repeatability`, vulnerable run 0 graded
  ERROR/ATTACK_MEASUREMENT_INVALID (the attack timing fell outside its valid band). The batch 3 code does not touch
  the latency path. Rerun alone with nothing else running: passes (376 s). Recorded as load-sensitive timing, not a
  verdict change. The full package has not passed in one run since this batch.

### Still open (blueprint P3)

- Blocked: AUTHN-007 (client-certificate validation) and GWAY-012 (TLS and upstream trust). The lab has no TLS
  listener. Both need one, with a real handshake. A TLS-level refusal is a transport failure, which grades as
  ERROR, so the fixed build must complete the handshake and refuse at the application layer, or the grader needs a
  rule for TLS-level refusal.


## Blueprint Phase 3: TLS listener, AUTHN-007 and GWAY-012 (the last two P3 scenarios)

### Decision (owner: user)

- Both builds complete the TLS handshake. The fixed build then refuses at the application layer, with the status the
  scenario declares.
- A TLS handshake failure grades ERROR, never PASS or FAIL, because the control under test was never reached.

### Built

- `lab/pki.go`: a lab CA, a server certificate for 127.0.0.1, ::1 and localhost, CA-signed client certificates, and
  self-signed client certificates for a forged identity.
- `lab/tls.go`: `Server.TLSConfig`. TLS 1.2 minimum in both builds. The server requests a client certificate but does
  not verify it during the handshake, in either build. Verification happens in the application.
- AUTHN-007 (`GET /api/mtls/orders/{id}`): the vulnerable build takes the identity from the certificate subject without
  checking the chain. The fixed build verifies the chain to the lab CA and refuses with 401. The attacker presents a
  self-signed certificate naming cust-a. Forbidden values are the other tenant's account and card references.
- GWAY-012 (`POST /api/gateway/upstream-fetch`): the gateway fetches a URL over TLS and relays the body. The vulnerable
  build skips certificate verification. The fixed build verifies against the lab roots and refuses with 422. The
  attacker points the gateway at a rogue upstream with an untrusted certificate, via the `{rogue_url}` placeholder.
  Forbidden value: the rogue upstream's probe marker.
- Runner: `Step.client_cert` names a certificate from `Config.ClientCerts`. A name the runner was not given is a
  transport error (ERROR). `Config.RootCAs` is the trust for the lab certificate. `Config.RogueURL` fills the
  `{rogue_url}` placeholder.
- Standalone binary: `apibas-lab -tls` serves HTTPS with a generated CA and server certificate. `-tls-ca PATH` writes
  the CA certificate so an operator can issue client certificates. Built and vetted; not exercised against a real
  client.

### Regression tests (`runner/phase3_tls_test.go`)

- Both builds complete the TLS handshake, including with a forged client certificate.
- The fixed build refuses a forged client certificate with 401 at the application layer, not as a transport failure.
- The fixed build refuses an untrusted upstream with 422 after a completed handshake.
- A runner that does not trust the lab CA grades ERROR for both builds, never PASS.
- A client certificate the runner was not given grades ERROR or SKIPPED, never a control result.

### Evidence

- `TestPhase3_TLSAcceptance`: both scenarios, both builds, pass. Three consecutive repeats of the TLS tests pass.
- The Phase 2 scope test, the earlier Phase 3 tests, the flaw-registry test and the timing-claim rules pass with 100
  catalog entries. The short suite is clean.

### Limits (stated, not hidden)

- GWAY-012 covers upstream certificate verification. TLS protocol-version and cipher policy is not graded. A
  version refusal is a handshake failure, which grades ERROR under the decision, so it cannot be a control result
  without a new rule.
- AUTHN-007 covers a self-signed certificate naming another tenant. Certificates issued by another CA, expired
  certificates, and revocation are not tested.
- Client certificates reach the runner through `Config.ClientCerts`. Nothing in the product provisions or stores
  real mTLS identities. The harness supplies them.
- The standalone `-tls` mode is built but has no end-to-end test.

### Blueprint P3 status

- All 39 P3 IDs in the blueprint table are now in the catalog (100 entries in total, including the earlier phases).
- Phase 3 is not closed in the blueprint sense. Its remaining work is the full runner re-verification, the QA open
  items, and the limits above. Protocol-level P3 items that are not in the table (async, SOAP, gRPC, WebSocket) are
  unchanged from the earlier QA log.
- Full `internal/apibas/runner` package (non-short, all suites): passed, exit 0, about 566 s.


## Blueprint Phase 3 close-out

### Closed

- All 39 blueprint P3 IDs are in the catalog and validated in both builds (`TestPhase3_CloseoutAllP3Validated`):
  vulnerable FAIL/exploited, fixed PASS/enforced. AUTHN-007 and GWAY-012 run on the TLS listener.
- Full runner package: `ok`, 512.6 s, exit 0. This run was on the close-out code, before batch 4a and 4b edits.

### Race spread (BIZ-005)

- Goroutine scheduling cannot be seeded, so there is no fixed seed. The race was measured over 100 runs per build
  (`TestPhase3_RaceFlakinessReport`):
  - vulnerable: 100 of 100 runs FAIL/exploited, with 5 accepted withdrawals in every run.
  - fixed: 100 of 100 runs PASS/enforced, with 1 accepted withdrawal in every run.
- Spread in this measurement: none in either build. Unexpected verdicts: 0.

### Protocol items

The blueprint rule: a protocol without an executable adapter and fixture is `UNSUPPORTED` and is never counted as
covered. `go test ./internal/apibas/protocol/` passes.

- GraphQL: adapter built. Used by ABUSE-004 and INJ-007.
- SOAP: adapter built. Used by INJ-005.
- Async: publish-form adapter built. Used by ABUSE-010 and INTEG-010. The consumer side is not modelled.
- gRPC: JSON-transcoding adapter only. DISC-009 claims that form. Native gRPC over HTTP/2 with protobuf descriptors
  is not built and is `UNSUPPORTED`.
- WebSocket: handshake adapter only. AUTHN-011 uses it. Frame-level behaviour is not built and is `UNSUPPORTED`.

### Correction

- Detection assertions are not a Phase 3 gap. The blueprint places them in Phase 4 (DET IDs, and the detection
  assertion on every P2/P3 scenario). An earlier entry listed them as a Phase 3 gap. That entry is corrected here.
  Batch 4c covers them.

### Limits

- TLS version and cipher policy is not graded (GWAY-012). A handshake refusal grades ERROR under the TLS decision.
- AUTHN-007 does not test another CA, expiry or revocation.
- Client certificates come from the harness (`Config.ClientCerts`). No real mTLS identity is provisioned.
- The standalone `apibas-lab -tls` mode is built but has no end-to-end test.
- Native gRPC and WebSocket frame adapters are not built (see protocol items).

### Status

Phase 3 is closed for the 39 blueprint P3 IDs against the lab fixtures. Nothing is claimed against live services.

## Blueprint Phase 4, batch 4a: DET-002, DET-005, DET-007 (existing rules)

### Built

- DET-002: three attempts with a revoked credential, repeated so REL-001 (repeated authentication failures) can fire.
  Graded `FAIL/exploited` in the vulnerable build and `PASS/enforced` in the fixed build.
- DET-005: the cross-customer order read, with its detection graded against the Elastic fixture. The test checks the
  detection report's provenance is the Elastic fixture label.
- DET-007: the forged identity header attack (the same request as AUTHN-008), graded for attribution. REL-004 is
  detected in the fixed build. It is not detected in the vulnerable build, where the header makes the request look
  like the owner's.

### Findings

- **Silent acceptance (DET-002).** The vulnerable build accepts a revoked credential with `200`. It logs no failure,
  so REL-001 cannot fire. The detection gap follows from the exploit: a control that accepts the credential produces
  no signal. The fixed build refuses it and REL-001 fires. This is the planted revoked-credential flaw, now seen from
  the detection side.
- **Forged-identity blind spot (DET-007).** The vulnerable build attributes the request to the header identity. REL-004
  does not fire there. This is the forged-identity blind spot the detection design already recorded.
- **REL-001 expectation now depends on the build.** It returns not_detected for a revoked credential in the vulnerable
  build, because no failure is produced. Other REL-001 scenarios are unchanged.

### Limits

- DET-005 checks routing against the single fixture SIEM only. The lab has one sink, so routing to a second SOC is not
  modelled. The check is provenance, not delivery to a SOC.
- DET-002 and DET-007 reuse the attacks of AUTHN-008 and the revoked-credential check. Each adds a distinct detection
  question on the same request.
- DET-008 is not built. The alert record has no object reference, so responders cannot be shown the affected object.
  It needs a change to the alert model, which is planned for a later batch.

### Evidence

- `TestPhase4_Batch4aDetectionAndVerdicts`: passes.
- The detection expectation table (`TestPhase34_DetectionMatchesDeclaredExpectations`) covers the three new blocks.
  Its full run is recorded below.

### Still open (Phase 4)

- Not built: DET-001, DET-003, DET-004, DET-006, DET-008, DET-010 and BIZ-012.
- The detection assertion on every P2 and P3 scenario is a Phase 4 criterion. Batch 4c covers it.


## Blueprint Phase 4, batch 4b: BIZ-012 and DET-003 (new rule REL-009)

### Built

- REL-009 (high-risk flow completed while a fraud control is degraded). It fires on a 2xx payment authorization while
  the lab reports the fraud check as degraded. Elastic fixture only.
- The lab access event now carries `degraded` (`lab/access.go`, `degradedDependencies`). The fraud check is the only
  dependency modelled. The detection event carries the same field (`detect/detect.go`).
- BIZ-012 (`API-BAS-BIZ-012`): the owner authorizes payment with the fraud check down.
  - vulnerable: FAIL/exploited, and REL-009 detected.
  - fixed: PASS/enforced (424, fails closed), and REL-009 not detected.
- Healthy control: with the fraud check up, an authorization completes in both builds and REL-009 stays silent.
  This is the first false-positive check for the rule (DET-006 is not complete; see limits).
- Detection expectation table: REL-009 added. Declared detection blocks are now 35, all matching.
  (`TestPhase34_DetectionMatchesDeclaredExpectations`.)
- `TestPhase4_Batch4bFraudControlAlert`: passes.

### DET-003 decision

- DET-003 (high-risk business-flow violations alert) is graded by BIZ-012's detection assertion. It is not a separate
  catalog scenario, because it would repeat the same request. Both IDs test one alert on one flow.

### Findings

- The rule has no event field for the fraud decision. The lab reports a dependency as degraded, not the decision
  itself. A rule that matches the completion of an authorization while a dependency is degraded is a proxy for the
  violation, not the violation. A completed authorization is only a violation when the fraud check was down.

### Limits

- REL-009 is not wired to the Sentinel fixture. The Sentinel record does not carry `degraded`. Sentinel routing is not
  graded for this rule.
- DET-006 (false positives) is only partly covered by the healthy control. Its full measurement is not done.
- The degraded flag is instance-wide, not per run. The lab's fault configuration is set for the whole scenario, so
  this is correct for these scenarios. It would not be correct if two runs shared one lab with different faults.
- DET-001, DET-004, DET-006, DET-008 and DET-010 are not built.

### Evidence

- `TestPhase4_Batch4bFraudControlAlert` and `TestPhase34_DetectionMatchesDeclaredExpectations`: passing.
- Full runner package for batch 4b: not yet run. Batch 4a and 4b are uncommitted.

### Still open (Phase 4)

- Not built: DET-001, DET-004, DET-006, DET-008, DET-010.
- The detection assertion on every P2 and P3 scenario (batch 4c).


## Blueprint Phase 4 closure: the gaps from batches 4a and 4b

Supersedes the "still open" lists of batches 4a and 4b. Decisions taken with the user: DET-003 stays a detection
assertion on BIZ-012 and is recorded there with `detection_covers`, so it is counted once. Coverage is checked by
`TestPhase4_DetectionStatusSweep`.

### Closed

- **DET-004, cross-identity correlation.** New scenario. Two identities make foreign-object reads in one run. The
  second identity's read is a `co_actor` setup step, and REL-010 (distinct identities reaching foreign objects, threshold
  two) fires in both builds. The attack is graded on its own: vulnerable FAIL/exploited, fixed PASS/enforced.
  - Contract extension: `co_actor` on a setup step allows a second identity from the preconditions to act, with its own
    token. The runner records that exchange and does not let its refusal end the chain. Only the final attack is graded.
  - `TestPhase4_DET004CrossIdentityCorrelation`.
- **DET-006, healthy and unhealthy controls.** Healthy owner reads, kept under the burst threshold, raise no alert. An
  unhealthy foreign read must raise REL-004, so the detector is shown to work. `TestPhase4_DET006HealthyAndUnhealthyControls`.
  - **Finding (false positive).** Twenty benign owner reads raise REL-005 (burst threshold ten). The rule counts requests
    regardless of their outcome, so ordinary volume alerts. The test records this; it is not tuned away. Whether the burst
    rule should exclude successful owner reads is a rule-design decision, not decided here.
- **DET-008, alerts name the affected resource.** `Alert` now carries the triggering action, the requesting identity and
  the owners named. The test checks the alert names `/api/orders/ORD-2001`, owner `cust-b`, identity `cust-a` (the verified
  customer identity, not the fixture name).
- **DET-010, investigable from retained evidence.** The alert's trigger event is among the run's retained access events,
  and it matches the alert's action and run tag. `TestPhase4_DET008DET010AlertsTraceToEvidence`.
- **DET-001, detection on attacks.** Every scenario that declares a detection block is graded against the rule's expectation.
  `TestPhase34_DetectionMatchesDeclaredExpectations`: 39 declared, 39 matching.
  - **Residual.** 66 scenarios are `not_evaluated`. Only three more were given REL-004 this round (DATA-001, DISC-003,
    INTEG-005), because they are single-identity foreign reads. The rest are multi-step, write, or protocol attacks
    that need their own rule analysis. DET-001 is therefore closed for the declared attacks and open for the 66.
- **DET-003 mapping.** `detection_covers: [API-BAS-DET-003]` on BIZ-012. The contract rejects an unknown or self-referencing
  DET ID, and a DET ID claimed by a catalogued DET scenario. The sweep fails if a DET ID is covered twice.
- **P2/P3 detection status sweep.** Every catalogued scenario has an explicit status: 39 `fixture_validated` (each with a
  detection block), 66 `not_evaluated` (each with a reason and no detection block). The two never mix. `not_evaluated` is
  not `not_detected`: a not_evaluated scenario has no detection result at all.
- **TLS gaps (Phase 3 close-out list).** `TestTLS_GapOtherCAAndExpiredClientCert`: a cust-a certificate from another CA,
  and an expired one. The fixed build refuses both at the application layer. The vulnerable build trusts the subject.
  `TestTLS_GapVersionBelowTLS12Refused`: a TLS 1.1 handshake is refused by both builds. The client may refuse TLS 1.1
  itself; the refusal is not proven to come from the server.

### Still open (named, not closed here)

- **DET-001 for the 66 undeclared attacks.** Needs per-scenario rule analysis (see above).
- **Certificate revocation (CRL/OCSP).** The lab has no revocation source. No revocation result is claimed.
- **Native gRPC over HTTP/2 and WebSocket frames.** Adapters cover the JSON-transcoding gRPC form and the WebSocket
  handshake only. These forms stay `UNSUPPORTED` until their adapters exist.
- **Standalone `apibas-lab -tls` end to end.** The binary has no end-to-end test.
- **Live SIEM validation.** Every detection result is fixture-validated. Nothing is claimed against a live SIEM.

### Evidence

- Targeted: `TestPhase4_DET*`, `TestPhase4_DetectionStatusSweep`, `TestPhase34_DetectionMatchesDeclaredExpectations`
  (39/39), `TestTLS_Gap*`: passing.
- Full `./internal/apibas/...` run on the final tree: see the result line recorded below.


## Blueprint Phase 4: DET-001 per-scenario analysis, standalone TLS, and the open gaps

### DET-001: per-scenario analysis of the not_evaluated scenarios

- Analysed individually: 66 scenarios (the scenarios that were `not_evaluated` before this pass). Each has a row in
  `docs/api-bas-det001-tracker.md` with its decision and justification.
- A detection rule was added only where the attack and the access-event telemetry justify it:
  - REL-005 (counted-request burst, threshold ten requests in one run): ABUSE-006, ABUSE-007, ABUSE-008, ABUSE-009,
    GWAY-009. Each repeats its attack ten times, so the volume is what the rule counts.
  - REL-004 (object owned by another identity): AUTHZ-002, DISC-010, GWAY-003, GWAY-004, GWAY-006, INTEG-006. Each names
    an order owned by another customer in the access event.
  - REL-009 (completed authorization while the fraud check is degraded): INTEG-007. The same flow as BIZ-012, graded
    separately. It does not change the DET-003 mapping on BIZ-012.
- 54 scenarios remain `not_evaluated`, each with its own reason. Examples: an anonymous request has no identity to
  attribute; a burst below the threshold of ten; a duplicate-key, prototype-key or header-injection attack that no
  injection class in the fixture covers.
- Two candidates were declared, validated, and reverted, because the evidence did not support them:
  - AUTHZ-004: the fixed build refuses the role change in setup, so the chain stops before the foreign object is
    reached. The fixed build produces no object-access event.
  - DATA-010: the signed file path does not name the order owner in the access event, so REL-004 cannot see the owner.
- **Defect found and fixed in the declarations.** The first REL-005 declarations used `min_severity: high`. REL-005 is
  medium, so the grade never counted it, even though the rule fired on 11 events. The declarations now use `medium`.
  The rule was not changed.
- Result: 51 scenarios are `fixture_validated` (each with a detection block). All 51 match the detection table in both
  builds (`TestPhase34_DetectionMatchesDeclaredExpectations`, with extraction off and on).

### Standalone TLS end to end

- `apibas-lab -tls` is now tested as a separate process. The test builds the binary, starts it, and drives the real
  handshake over TCP (`TestTLS_StandaloneLabEndToEnd`, both builds).
  - The server certificate verifies against the CA the binary writes. An empty root pool fails the handshake.
  - A client with the cust-b certificate the binary issues reads cust-b's order (200) in both builds.
  - A self-signed cust-b certificate is trusted in the vulnerable build (200) and refused by the fixed build with 401.
    The handshake completes in both.
  - No client certificate: 401 from the application, after the handshake completes.
  - TLS 1.1 is refused at the handshake.
- New flags on the binary: `-tls-client-cert` and `-tls-client-key` write a cust-b client certificate and its key, so the
  trusted path can be exercised. Without them the test could not present a trusted certificate.

### Open gaps (kept visible; none counted as validated)

These are printed by every coverage report (`coverage.KnownGaps`, `TestKnownGapsAlwaysPrinted`).

1. **Native gRPC over HTTP/2 with protobuf descriptors: UNSUPPORTED.** The adapter covers the JSON-transcoding form only.
   DISC-009 claims that form. It does not imply full gRPC coverage.
2. **WebSocket frame behaviour: UNSUPPORTED.** The adapter covers the handshake only. AUTHN-011 claims the handshake.
3. **Certificate revocation (CRL/OCSP): not tested and not claimed.** The lab has no revocation source. A successful
   handshake does not prove revocation checking, so no revocation result is recorded.
4. **Live SIEM validation: not done.** Every detection result is fixture-validated, labelled `fixture_validated` in
   the catalogue. Live validation needs a real SIEM integration and a controlled environment, and will be planned
   separately.
5. **Detection for the 54 not_evaluated scenarios.** Each has a reason in the tracker. Detection is claimed only where
   the telemetry supports it.


### Update: owner attribution for DATA-005 and DATA-010

This update corrects the DET-001 section above. The earlier count and the DATA-010 revert are superseded.

- **Lab change (attribution).** The lab named an owner only when an order ID was a whole path segment, or a query value
  contained the order ID. Two cases were missed:
  - an order ID embedded in a path segment (`ORD-1001-statement`): the owner is now attributed;
  - a query value that contains a protected value of an order (`account_ref=BAS-SIM-ACC-A`): the value's owner is now
    attributed.
  The detection table mirrors both rules (`ownershipDetection`, `protectedValueNamed`).
- **Now declared (REL-004):** DATA-005 (filter names another customer's protected account value) and DATA-010 (signed
  file path names another customer's order). DATA-010 was reverted earlier only because the lab did not attribute the
  owner. That is now fixed, so the declaration stands.
- **Corrected counts:** 66 scenarios analysed. 14 have a detection rule, all validated in both builds with extraction
  off and on, and the table has 53 declared scenarios with none mismatched. 52 remain `not_evaluated`, each with a reason
  in `docs/api-bas-det001-tracker.md`.
- **Defect in the declaration step, not the rule.** The first DATA-005 expectation was wrong: the table derived the owner
  only from the order ID, so it expected not_detected. The lab's attribution was right. The table now mirrors it.
- **Still open for DET-001 (52 scenarios, grouped by what is missing; the groups add up to 52):**
  - **Anonymous, no identity to attribute (9):** AUTHN-001, DISC-002, DISC-004, DISC-005, DISC-006, DISC-007, GWAY-002,
    GWAY-010, INTEG-009. Needs a policy decision on attributing anonymous access. INTEG-002 is in the burst group instead.
  - **Identity-forged blind spot (3):** AUTHN-003, AUTHN-007 (the forged subject is the owner's, the DET-007 blind spot)
    and AUTHZ-004 (the fixed build refuses in setup, so no object access is made).
  - **Own-object actions with no privileged class (12):** AUTHN-010, AUTHZ-003, BIZ-001, BIZ-002, BIZ-006, BIZ-007,
    BIZ-009, DATA-007, DATA-008, DATA-009, GWAY-008, INTEG-001. Needs a decision on which actions are privileged.
  - **Not telemetry the access event carries (9):** ABUSE-002, ABUSE-003, ABUSE-004, ABUSE-005 (single requests, size or
    depth), AUTHN-004 (redirect URI), AUTHN-011 (WebSocket origin), DATA-006 (cache headers), DISC-008 (backend host in a
    not-found body), INTEG-010 (async consumer). These need new fields or are response properties.
  - **Injection-shaped with no signature class (5):** GWAY-005, INJ-006, INJ-009, INJ-011, INJ-012. Needs new classes with
    true-positive and false-positive tests.
  - **Destination-based, no destination field (4):** GWAY-012 (upstream TLS trust), INTEG-003 (SSRF), INTEG-004 (open
    redirect), INTEG-011 (callback host). Needs new fields and new classes.
  - **Below the burst threshold (9):** AUTHN-002, AUTHN-005, AUTHN-009, BIZ-003, BIZ-004, BIZ-005, BIZ-008, BIZ-010,
    BIZ-011. Kept `not_evaluated` by design: lowering the threshold would raise false positives.

### Counts, kept distinct

- Declared scenarios in the catalogue with a detection block (fixture_validated): 53. All 53 match the detection table.
- DET-001 rule coverage added this pass: 14 of the 66 scenarios that were not_evaluated before the DET-001 analysis.
- not_evaluated across the catalogue: 52. Each has a reason; none has a detection result. not_evaluated is never counted as not_detected.
- Full ./internal/apibas/... run on this tree: all packages ok, the runner package 486.7 s, exit 0.


## Blueprint Phase 4: policy-driven rule groups (anonymous attribution, privileged class)

### Anonymous attribution (REL-011)

- **Rule.** REL-011 fires when a request with no identity succeeds (2xx) on an object that has an owner. It correlates on
  the request (run), the target (the owner the request reached) and the behaviour (the 2xx outcome).
- **Not correlated: source address.** The access event carries no source address, so no source-based anonymous rule
  exists. This is stated in the rule and is not claimed.
- **Declared (7, all validated in both builds):** AUTHN-001, DISC-002, DISC-004, DISC-006, GWAY-002, GWAY-010, INTEG-009.
  In the vulnerable build each serves the anonymous attack and REL-011 fires; in the fixed build the attack is refused and
  REL-011 does not fire.
- **Insufficient telemetry, kept `not_evaluated` with that reason (3):** DISC-005, DISC-007, INTEG-002. Each anonymous
  request names no owned object, so REL-011 has no owner to match.
- **Tests.** `TestRel011AnonymousSuccessOnOwnedObject` covers the positive case (anonymous 200 on an owned order), a refused
  anonymous request, an anonymous success with no owned object, and an authenticated owner success.

### Privileged action class (REL-007)

- **Class.** `detect.ActionClass` defines the explicit class. Privileged: any route under `/api/admin/`, the self-assigned
  role change (`PATCH /api/me/role`), payout approval and refund (`POST .../approve-payout`, `POST .../refund`), key rotation,
  the key status change, and the authorization audit and delete routes. Ownership alone never makes an action privileged.
- **Event field.** The lab sets `action_class` on every access event from the same definition the rule reads, so the lab
  and the rule cannot disagree.
- **Declared (3):** BIZ-001 (customer refund), BIZ-007 (payout approval by the maker), AUTHZ-004 (self-assigned role change).
  REL-007 fires on the attempt in both builds. The privileged call is made whatever the outcome; this is the same design as
  REL-005.
- **Negative tests.** `TestActionClassOrdinaryOwnedObjectAccessIsNotPrivileged` checks that ordinary owned-object reads,
  updates, exports, closes, withdrawals and status changes carry no class. It also checks that a prefix look-alike such as
  `/api/admin-notes` is not administrative.
- **Not classed as privileged, by policy:** sensitive exports (DATA-007). The lab serves export to the owner as an ordinary
  action, so it is not modelled as privileged. It stays `not_evaluated`.

### Counts after this round

- Declared scenarios with a detection block (fixture_validated): 63. All 63 match the detection table in both builds.
- not_evaluated across the catalogue: 42. Each has a reason in `docs/api-bas-det001-tracker.md`.
- Groups still `not_evaluated`, pending the telemetry work: injection-shaped with no signature class (5), destination-based
  with no destination field (4); not telemetry the access event carries (9); own-object actions with no privileged class by
  policy (10); the identity-forged blind spot (2: AUTHN-003, AUTHN-007); below the burst threshold (9).

### External gaps (visible; none counted as validated)

These are printed in every coverage report (`coverage.KnownGaps`).

1. Native gRPC over HTTP/2 with protobuf descriptors: UNSUPPORTED.
2. WebSocket frame behaviour: UNSUPPORTED.
3. Certificate revocation: no revocation source; not tested and not claimed.
4. Live SIEM validation: not done. Every detection result is fixture-validated.


## Blueprint Phase 4: injection classes and destination telemetry

### Injection (REL-006)

- The lab's existing `signature` field is the injection class list on each event. It is reused as the `injection_class`
  field, so the lab does not carry a second parser.
- Two classes are added, each on a structural pattern, not on one payload:
  - `cookie_attribute`: a cookie attribute injected after a semicolon (`; Domain=`, `; Path=`, `; Max-Age=`, `; SameSite=`,
    or the flags `HttpOnly` and `Secure`).
  - `prototype_key`: a prototype key in key position (`"__proto__":`, a `__proto__.` path, or `constructor.prototype`).
    The same word as a string value does not match.
- **Declared (2):** INJ-009 (cookie attribute in a note) and INJ-011 (`__proto__` key in an attribute merge). Both are
  detected only with body extraction on, because the body is inspected only then; with extraction off they are not
  detected, as INJ-003 already is.
- **Not classed (3), kept `not_evaluated`:** INJ-006 (duplicate JSON keys), INJ-012 (form-encoded bypass of validation),
  GWAY-005 (duplicate Content-Type). Each is a parser differential or a validation bypass, not an injection pattern. The
  policy does not label them as injection.
- **Tests.** `TestInjectionClassCookieAttribute` and `TestInjectionClassPrototypeKey` cover the positive patterns and the
  ordinary text that must not match.

### Destination (REL-012)

- **Field.** The access event carries `destination` (normalised `scheme://host:port`) and `destination_policy`. A handler
  records the destination it acts on, through `noteDestination`, from the request context. Destinations are never read
  out of arbitrary body text.
- **Policy.** `lab.DestinationPolicy` is the single definition. Verdicts: `allowed`, `outside_allowlist`, `internal`.
  - redirect: a relative path is allowed; any absolute URL is outside policy (no redirect allowlist exists).
  - callback: an allowlisted host is allowed; a loopback, private, link-local or unspecified address is internal;
    anything else is outside policy.
  - webhook test: an internal address is internal. A public host is allowed, because the lab has no webhook allowlist, so
    a public host is not a violation.
- **Rule.** REL-012 fires on `outside_allowlist` or `internal`, whatever the outcome. The attempt is the signal, as with
  REL-005 and REL-007.
- **Declared (3):** INTEG-003 (webhook test to an internal address, SSRF), INTEG-004 (return redirect off this origin),
  INTEG-011 (callback to a host that is not allowlisted). All three validate in both builds.
- **Not declared, kept `not_evaluated`:** GWAY-012. The upstream fetch acts on a URL, but the lab has no destination
  policy for upstream fetches, and the access event carries no certificate trust. Its intended behaviour (certificate
  verification) is not observable from the event, so the field existing does not make it validated.
- **Tests.** `TestNormalizeDestination`, `TestDestinationPolicyByKind`, `TestDestinationPolicyUnknownKindIsNotEvaluated`
  (lab), and `TestRel012DestinationPolicy` (detect).
- **Defect found in the expectation, not the rule.** INTEG-003's body uses the `{lab_url}` placeholder. The expectation
  read it as a relative path. The runner substitutes the lab's loopback address, so the destination is internal. The
  expectation now substitutes the placeholder the same way the runner does.

### Counts

- Declared scenarios with a detection block (fixture_validated): 68. All 68 match the detection table in both builds.
- not_evaluated across the catalogue: 37. Each has a reason in `docs/api-bas-det001-tracker.md`.

### Still open in Phase 4

- **Identity-forged blind spot (AUTHN-003, AUTHN-007).** Not started. The fix is to record the trusted identity from the
  lab's authentication context separately from any identity claimed in a header, then flag mismatches. Until then these
  stay documented gaps.
  *Superseded 4 November 2026: REL-013 already compares the verified identity with the claimed one and fires on both scenarios (fixture-validated). The remaining work is attribution clarity; see the design "Identity attribution for AUTHN-003 and AUTHN-007" below.*
- **Action class vocabulary.** Only `privileged` exists. The policy asks for a small vocabulary (read, write,
  privilege_change, sensitive_export, financial_approval, security_control_change). Not started.
- **Telemetry groups still unevaluated.** ABUSE-002 to 005, AUTHN-004, AUTHN-011, DATA-006, DISC-008, INTEG-010: each
  needs its own evidence (request cost, handshake context, object disclosure, integration action), and each stays
  `not_evaluated` until the lab can observe it.
- **Own-object actions.** AUTHN-010, AUTHZ-003, BIZ-002, BIZ-006, BIZ-009, DATA-007, DATA-008, DATA-009, GWAY-008, INTEG-001
  stay unevaluated by policy: ordinary own-object access is not privileged.
- **Below the burst threshold.** Stays unevaluated by design.

### External gaps (visible; none counted as validated)

1. Native gRPC over HTTP/2 with protobuf descriptors: UNSUPPORTED.
2. WebSocket frame behaviour: UNSUPPORTED.
3. Certificate revocation: no revocation source; not tested and not claimed.
4. Live SIEM validation: not done. Every detection result is fixture-validated.


## Blueprint Phase 4: remaining groups, round 2

### Newly declared (fixture_validated)

- **ABUSE-003** (REL-014, page size above the documented maximum of 100). The access event records the requested page size. The vulnerable build serves a 100000-item page and the fixed build refuses it with 400. The rule fires on the attempt, whatever the outcome.
- **ABUSE-005** (REL-015, request body above the 1 MiB upload ceiling). The access event records the body size as sent. The vulnerable build accepts a 2 MiB attachment and the fixed build refuses it with 413.
- **DATA-006** (REL-016, owner data served as publicly cacheable). The access event records the response Cache-Control. The vulnerable build marks the owner status response public; the fixed build marks it private, no-store.
- **AUTHN-004** (REL-012, redirect outside policy). The authorize endpoint now records its redirect_uri as a destination, with its own policy: only the one registered redirect is allowed.
- **GWAY-012** (REL-017, upstream content relayed without certificate verification). The gateway verifies the upstream chain itself, whatever the build's skip setting, and records the verdict. REL-017 fires only on a relayed (2xx) response from an untrusted chain. Graded on the TLS environment by its own test.
- **AUTHN-007** (REL-013, identity not proven by a signed certificate). The access event records the client certificate's common name as the claimed identity, and the identity a chain to the lab CA proves as the verified identity. Graded on the TLS environment by its own test.

### Defects found while doing this

- **Body extraction truncated request bodies.** With body extraction on, the middleware replaced the body with its first 64 KiB. Any upload larger than that was seen by the handler as truncated, so the fixed build's size check could not refuse it. The handler now receives the whole body; the owner and injection inspection still reads only the 64 KiB prefix.
- **Stale lab binaries.** The loopback labs were started before the event fields changed, so a direct run recorded no request size. Labs must be restarted after a rebuild. The detection table runs its own labs and is not affected.

### Counts

- Declared scenarios: 75 fixture_validated. The detection table grades 73 in both builds, all matching. GWAY-012 and AUTHN-007 are graded by their own TLS tests, because the table has no TLS harness; the sweep counts them as declared.
- not_evaluated: 30. Each has a reason in `docs/api-bas-det001-tracker.md`.

### Still not_evaluated, with the reason each stays

- **Below the burst threshold (9):** AUTHN-002, AUTHN-005, AUTHN-009, BIZ-003, BIZ-004, BIZ-005, BIZ-008, BIZ-010, BIZ-011. The threshold is not lowered. By design.
- **Anonymous, no owned object (3):** DISC-005, DISC-007, INTEG-002. Nothing to attribute. By design.
- **Own-object actions (10):** AUTHN-010, AUTHZ-003, BIZ-002, BIZ-006, BIZ-009, DATA-007, DATA-008, DATA-009, GWAY-008, INTEG-001. Classified (write, read, sensitive_export). Each claim concerns stored state, a response property or a step-up check that the access event does not record.
- **Single request, cost or enumeration (2):** ABUSE-002 (expensive report; a work-unit budget is not documented), DISC-008 (a single not-found has no enumeration signal).
- **Protocol adapters (2):** ABUSE-004 (GraphQL depth), INTEG-010 (async consumer). No adapter.
- **External gap (1):** AUTHN-011, WebSocket handshake; native frames are unsupported.
- **Parser differentials, not injection (3):** GWAY-005, INJ-006, INJ-012. Policy classes these as parser or validation issues. A rule family for them is a policy decision, not a telemetry gap.

### External gaps (visible; none counted as validated)

1. Native gRPC over HTTP/2 with protobuf descriptors: UNSUPPORTED.
2. WebSocket frame behaviour: UNSUPPORTED.
3. Certificate revocation: no revocation source; not tested and not claimed.
4. Live SIEM validation: not done. Every detection result is fixture-validated.


## Blueprint Phase 5: sector and regional packs (first slice)

### Built

- **Regulatory registry** (`orchestrator/internal/apibas/regulatory`). Every mapping names its control reference, framework, clause, source provision, version and an https source URL, and cites the scenarios it maps. Status defaults to `unverified`.
  - An unverified mapping carries no effective date, and cannot claim its commencement is verified.
  - A `verified` mapping needs the full review record: a reviewer, a review date (YYYY-MM-DD), the exact source provision, applicability conditions, commencement verified, an effective date, and an https commencement source. A source URL alone does not make a mapping verified.
  - A test checks that every scenario's reference resolves in the registry and that each registry entry lists its scenarios back.
- **Commencement is separate from enactment.** The DPDP Section 12 record has `commencement: not_verified` and an empty effective date.
- **DATA-011, erasure retention** (`API-BAS-DATA-011`). The owner erases their own order, then reads it again. The test reads persisted state before the runner resets the lab, and checks the owner's later read and its protected value.
  - Vulnerable build: the erasure is acknowledged (202), the record stays in state, the read is 200 and returns the protected value. Result FAIL, exploited.
  - Fixed build: the record is removed, the read is 404 with no protected value. Result PASS, enforced.

### Grader change: state snapshot taken before the attack

The state change used to be measured from after the baseline, so a setup step's legitimate change counted as the attack's effect. The snapshot is now taken immediately before the attack step.

Verdict comparison, old runner against new runner over the same catalogue and labs (`orchestrator/internal/apibas/catalog`, both builds):
- 92 existing scenarios: identical verdicts in both builds.
- The four scenarios with setup steps (AUTHN-006, AUTHZ-004, DET-004, DATA-011) were compared individually. None changed.
- The one difference is DATA-011, which the old runner does not know.

### Verified

- Full `./internal/apibas/...` run on this tree: all packages ok, exit 0.
- Windows cross-compile of `./cmd/server`, `./cmd/apibas-lab` and `./cmd/apibas-runner`: ok.

### Still open in Phase 5

- **Regulatory mappings:** none added. Official sources for RBI, CERT-In, CBUAE and UAE PDPL have been located but not read, so no provision is recorded and no applicability is decided. DPDP Section 12 stays `unverified` until its commencement is confirmed from an official notification.
- **Review:** no mapping has a reviewer. A named reviewer is needed before any mapping can be `verified`.
- **Sector packs:** NBFC, manufacturing, healthcare, and retail/logistics/telecom are not built. Each needs reusable domain objects in the lab first (loan applications, production orders, patient records, subscriber usage).
- **Statement:** a passing scenario demonstrates a control outcome. It does not certify compliance.


## Blueprint Phase 5: source capture and candidate mappings (update)

This update replaces the "no regulatory mapping added" statement above. It is a candidate record, not a legal approval.

### Sources captured

Seven official documents, provided in `API_Phase5/`, copied byte-for-byte to `orchestrator/internal/apibas/regulatory/sources/`. The registry test recomputes each SHA-256 from the committed bytes and fails on any change. Retrieval date for the research: 21 October 2026. Hashes are of the exact file bytes.

| File | SHA-256 |
|---|---|
| in-dpdp-act-2023.pdf | 4deb23981d3010c8225a2ff6149e7243dc2268455b299e283afebdd7b72a7d15 |
| in-rbi-it-governance-directions-2023.pdf | 8ad6286676b298038b2dda8f6a6bc4014c2a3fe6f0b5c59b1b02fcaf77cb5f81 |
| in-certin-directions-70b-2022-04-28.pdf | 202c2f3953d792dcfb3ecb3634fc82ab75437ee596de89b8d59a211e8e42431f |
| in-certin-faq-2022-05.pdf | 7c4ae9eab453db32a5feece63987f7606373d689755b5b2869bb367b5682d6af |
| in-certin-extension-2022-06-27.pdf | f0a2805f2a3bd0745560d417ffb6d41bf2cfe9920a5fd8a45b806ff10d61979f |
| ae-pdpl-decree-law-45-2021.pdf | d5d5f9e93bd6c0dc2afe79776f3101bcd599e4400a67309bc0b378b2812bcf3a |
| ae-cbuae-consumer-protection-standards.pdf | b9899e547acca33d117e55b219852a633820b28ee57b0a0dd47644dcdca54987 |

### Clause checks against the captured text

- **DPDP Section 12(3)** is the erasure duty. The earlier mapping said Section 12, and the Act's text confirms 12(3). Enactment is 11 August 2023 per the Act. Commencement is not verified: Section 1(2) makes each provision come into force on a date notified in the Official Gazette, and no notification is in the source set.
- **UAE PDPL Article 15(2)** is the erasure right, with exceptions in 15(3). The earlier mapping of Article 13 was wrong: Article 13 is the information right, and its erasure reference is only a description of the procedure. Article 31 gives entry into force on 2 January 2022, which is verified from the text. The Executive Regulation is not in the source set.
- **RBI paragraph 19(a)** (access controls) is mapped as a candidate to AUTHZ-001. Commencement is verified from paragraph 1(c): 1 April 2024.
- **CERT-In six-hour reporting** is paragraph (ii) of the Directions, not "3(i)" as the research draft said. Paragraph (i) is the NTP clock requirement. The MSME extension sets 25 September 2022 for covered MSMEs.
- **CBUAE** clauses 6.1.2.6 and 6.1.7.2 are confirmed. The document is titled "Consumer Protection Standards", not a regulation.

### Mapping status and coverage

- Candidate mappings, all `unverified`: DPDP 12(3) to DATA-011; UAE PDPL 15(2) to DATA-011; RBI 19(a) to AUTHZ-001.
- Each mapped scenario has a coverage entry stating what it tests and what it does not. Examples: DATA-011 does not test the Article 15(3) exceptions, the prescribed request manner, or the export, status and statement paths. AUTHZ-001 does not test the ITSC-approved procedures, supervision of elevated access, or multi-factor authentication.
- Unmapped, with reason and required scenario: CERT-In paragraph (ii) reporting timing; CBUAE 6.1.2.6 significant breach notification; CBUAE 6.1.7.2 material breach notification.

### Not done

- No mapping has a reviewer, a review date, or a reviewed hash. None is verified.
  *Superseded 21 October 2026: RBI 19(a) and UAE PDPL 15(2) are verified by Zain (see the verification record). DPDP section 12 stays unverified.*
- DATA-011 is not yet checked against every owner read path.
  *Superseded: DATA-012 (summary) and DATA-013 (export) cover the other owner read paths; a status read carries no protected value, so it is not a leak scenario.*
- Scenario-level behaviour for the unmapped obligations is not built: a breach-notification scenario, and a reporting-timeline scenario.
  *Superseded: REPORT-001 and REPORT-002 were built in Phase 6 (see that section). Their stated gaps are listed under Phase 6.*
- The source URLs were taken from search results and have not been fetched. The committed PDFs are the bytes the registry tests.

## Blueprint Phase 6: reporting-workflow engine extension and notification scenarios

### Inspection (before building)

The grader (`grade.Assess`) grades HTTP exchanges and a state diff only. Steps cannot pass a value from one response to the next, and nothing graded deadlines, recipients or receipts. The lab had no reporting route. The smallest compatible extension was therefore a separate evaluator, not a change to `Assess`, so existing scenario verdicts cannot move.

### What was built

- `internal/apibas/reporting`: pure evaluator. Each obligation has its own recipient, deadline (from the scenario, which cites the provision), and provision reference. An empty deadline means the provision states no number, so the obligation is SKIPPED, not graded against an invented value. A dispatch missing its timestamp, payload hash, receipt or mode fails. A simulated dispatch never yields a genuine receipt. 16 unit tests.
- `internal/apibas/lab/reporting.go`: fixture receiver, identical in both builds. Seeded incidents with fixed awareness times. Admin fault injection (delay, failed recipient, omitted receipt, misroute). Dispatches never leave the lab.
- Contract: `REPORT` category (a taxonomy addition), `reporting` block (incident, obligations, validated), ground-truth adapter `reporting`.
- Runner: `gradeReporting` replaces the HTTP grade only where that grade is not already ERROR or FAIL. The grade reads the lab's dispatch record, not the HTTP reply.
- Scenarios: `API-BAS-REPORT-001` (CERT-In, 6h from IN-CERTIN-70B-II), `API-BAS-REPORT-002` (CBUAE 6.1.2.6 and 6.1.7.2, no numeric deadline).

### Results

- Unit tests: `go test ./internal/apibas/reporting/` passes.
- Runner cases (`TestPhase6_*`), both builds: REPORT-001 on time PASS; exactly at deadline PASS; late by one second FAIL `deadline_missed`; failed dispatch FAIL `dispatch_failed`; receipt missing FAIL `evidence_missing`; misrouted FAIL `wrong_recipient`. REPORT-002 dispatched with no numeric deadline SKIPPED `deadline_not_defined_by_provision`; failed, misrouted and receipt-missing FAIL. Unreachable target ERROR; no reporting adapter ERROR.
- Every simulated run is labelled `simulated` and reports `genuine_receipt=false`.
- Full apibas suite (`go test ./internal/apibas/... -count=1`): EXIT 0.

### Decisions

- Faults are harness configuration; the pre-run lab reset keeps them. Harness clears them with an empty set.
- The CBUAE scenario never PASSes on timeliness until a provision-derived deadline is recorded and reviewed.
- The registry's CERT-In and CBUAE unmapped records moved from `not_implemented` to `implemented_not_validated`. They remain unmapped and unverified.

### Not done (stated gaps)

- No live reporting channel. A simulated PASS is a workflow check only; it does not prove submission to CERT-In or the Central Bank.
- No provision-derived deadline for CBUAE clauses 6.1.2.6 and 6.1.7.2.
- No human reviewer has approved any mapping.

## Mapping verification record (21 October 2026)

Reviewer: Zain (human approval given in chat, 21 October 2026).

- **IN-RBI-ITGRC-19A → API-BAS-AUTHZ-001: verified.** Commencement verified from paragraph 1(c) (1 April 2024). Reviewed hash equals the committed source hash (`8ad6286676b298038b2dda8f6a6bc4014c2a3fe6f0b5c59b1b02fcaf77cb5f81`). Coverage gaps (19(a) procedures, 19(b) supervision, 19(c) MFA, staff access) stay recorded on the mapping.
- **UAE-PDPL-A15-2 → API-BAS-DATA-011: verified.** Commencement verified from Article 31 (2 January 2022). Reviewed hash equals the committed source hash (`d5d5f9e93bd6c0dc2afe79776f3101bcd599e4400a67309bc0b378b2812bcf3a`). The Executive Regulation is not in the source set and stays a recorded gap.
- **IN-DPDP-S12-3 → API-BAS-DATA-011: not verified.** The registry requires verified commencement, and the notification bringing section 12 into force is not in the source set. It stays `unverified` until that notification is captured and reviewed.
- Unmapped obligations (CERT-In paragraph (ii), CBUAE 6.1.2.6 and 6.1.7.2) are unchanged and not verified.

Verification is the scoped human decision recorded here. It does not change scenario results. The scenarios remain lab validation only; no live regulatory channel is validated.

## NBFC sector pack (21 October 2026)

Fixture: `fixture.NBFCTwoBorrower()` (`nbfc-two-borrower`). Two borrowers, one loan officer and one administrator. All identities, amounts and KYC details are synthetic; every protected value carries the `BAS-SIM` tag. Scenarios use the existing AUTHZ and DATA categories; the pack adds no taxonomy category.

### Scenario mapping

| Pack item | API-BAS ID | Claim | Denied statuses | Detection assertion |
|---|---|---|---|---|
| NBFC-001 borrower reads another's loan | AUTHZ-101 | cross_identity | 403, 404 | fixture_validated (REL-004) |
| NBFC-002 borrower retrieves another's KYC | DATA-101 | cross_identity | 404 | fixture_validated (REL-004) |
| NBFC-003 borrower changes another's application | AUTHZ-102 | cross_identity | 404 | fixture_validated (REL-004) |
| NBFC-004 officer approves unassigned loan | AUTHZ-103 | cross_identity | 403, 404 | fixture_validated (REL-007, REL-004) |
| NBFC-005 officer approves own prepared decision | AUTHZ-104 | cross_identity | 403 | fixture_validated (REL-007, REL-004) |
| NBFC-006 borrower alters repayment | AUTHZ-105 | property_level | 403 | fixture_validated (REL-018) |
| NBFC-007 loan read exposes KYC fields | DATA-102 | property_level | clean_is_enforcement | **not_evaluated (gap, see below)** |
| NBFC-008 loan list reveals other loans | DATA-103 | cross_identity | clean_is_enforcement | fixture_validated (REL-004, response-owner attribution) |
| Statement with debit mandates | DATA-104 | cross_identity | 404 | fixture_validated (REL-008, REL-004) |
| Administrative access policy | AUTHZ-106 | cross_identity | 403 | fixture_validated (REL-019, REL-007, REL-004) |

### Administrative access and audit

- `GET /api/nbfc/admin/loans/{id}` requires the administrator role and the `loans:read` grant. `GET /api/nbfc/admin/kyc/{id}` requires `kyc:read`, which the fixture does not grant to the administrator. A role alone is not a grant.
- The fixed build refuses a borrower (403) and an administrator without the grant (403). The vulnerable build skips both checks.
- Every attempt is audited in both builds: identity, role, action, target, grant, outcome (`allowed` or `denied`) and reason. `GET /lab/nbfc/audit` is admin-only and cleared on reseed.
- Tests (`runner/phase7_admin_test.go`): authorized administrator succeeds with 200 and public fields only; administrator without grant denied; borrower denied with audit role `borrower`; vulnerable build serves the protected value and audits it as `allowed`; audit order and content for a two-attempt run.

### Detection

- Event model: `ActorRole` is recorded on each access event (fixture role, `customer` for other authenticated identities, empty when anonymous).
- New rules: REL-018 (repayment changed by a non-staff identity) and REL-019 (privileged route called without the administrator role). Both are judged on the attempt, so they fire in both builds.
- New action classes: `/api/nbfc/admin/` is `privilege_change`; POST `/decision` is `financial_approval`.
- Response-owner attribution: the loan list names the owners of the records it returns, so REL-004 can judge a list that discloses another owner's loan (NBFC-008). The fixed build returns only the caller's loans and does not fire.
- Detection expectations are fixture-derived in `runner/phase34_detection_test.go`. Unit tests in `detect/nbfc_test.go`.

**Detection gap, stated:** NBFC-007 (DATA-102) stays `not_evaluated`. The loan read carries KYC identity evidence through a projection. REL-008 covers foreign-owned projections only, and the access event does not record which fields a response returned, so no rule can grade it. It is not claimed as detected.

### Results

- `TestPhase7_NBFCScenariosBothBuilds`: all ten NBFC scenarios FAIL exploited on the vulnerable build and PASS on the fixed build.
- Admin and audit tests (`TestPhase7_Admin*`, `TestPhase7_Borrower*`, `TestPhase7_AuditRecordsEveryAttempt`): pass.
- Detection unit tests (`go test ./internal/apibas/detect/`): pass.
- Full apibas suite (`go test ./internal/apibas/... -count=1 -timeout 60m`): EXIT 0. Runner package took about 9 minutes.
- Scenario count after this pack: 120 catalogue scenarios (AUTHZ 18, DATA 17, others unchanged).

### Regulatory

- RBI AUTHZ-001 is **not** extended to any NBFC scenario. The pack needs a fresh applicability review first.
- The NBFC scenarios carry `regulatory_mapping: []`. Industry references in each YAML are descriptive only.
- No mapping was verified or proposed for the pack. Human reviewer approval is required for each mapping.
- Reconfirmation needed: the coverage-gap text for UAE-PDPL-A15-2 / DATA-011 changed to point at DATA-012 and DATA-013 (see `registry.yaml`). Reviewer Zain should reconfirm that wording; the verification itself was not altered.

### Stated gaps

- Field validation against a live NBFC deployment has not been done.
- NBFC-007 detection is not implemented (see above).
- The Executive Regulation for PDPL is not in the source set (carried over).

## Platform decisions for production (21 October 2026)

Decided by the product owner. Implementation follows these.

### Results and retention
- Store: the orchestrator's existing PostgreSQL, through a new migration.
- Persist run metadata, scenario verdicts, exploitability results, detection outcomes, evidence references, hashes, timestamps, and target and build fingerprints.
- Do not store raw HTTP request or response bodies by default. Redact secrets and protected values. Keep hashes and the minimum evidence needed to verify an outcome.
- Retention: 90 days by default, configurable per installation.

### Access
- A dedicated API BAS read permission governs results and reports. Run-management permission does not grant result access.
- Admin access to results is explicit and audited.

### Execution
- Use the existing `internal/jobs` machinery, plus a manual "Run now" action.
- Every run references a named target, scenario set and environment. A general run request may not supply an arbitrary target URL.
- Live targets require explicit operator approval for each live run. A target-level approval flag alone is not sufficient.
- Enforce concurrency limits, timeouts, cancellation and bounded retries. Never automatically retry a potentially state-changing live scenario.
- No production schedules are enabled by default.

### Secrets
- Preferred: the platform's existing secret mechanism, if it meets three conditions: encrypted storage, access controls, and auditability.
- Fallback: Vault or another approved external secret manager.
- Credentials are referenced per target. A run gets access only when it needs it. Secrets are never copied into job records, result records or logs.
- Environment variables are for the local lab and development only. Production environment injection is a temporary exception.
- Rotation is an open decision. Nothing in this log implies rotation is implemented.

**Verification of the existing mechanism (done 21 October 2026): it does not meet the condition.**
- Connector and SIEM credentials are stored in plain `text` columns (`client_secret`, `token`, `password`, `api_token`, `sso_configs.client_secret`, `notification_webhooks.secret`; `internal/db/postgres.go`).
- The `pgcrypto` extension is created at startup, but no code calls `pgp_sym_encrypt` or `pgp_sym_decrypt`, and no application key exists.
- The schema comment says protection relies on disk-level TDE or LUKS. That is not column-level encryption.
- Audit: connector create, update and delete are audited (`internal/api/action_handlers.go`). API responses mask `client_secret`.
- Consequence: the API BAS secret store uses the Vault fallback. This also raises a separate finding: existing platform credentials are plaintext at the column level. That is not a regression from this decision, and fixing it is outside API BAS. It needs its own decision.

### Timing qualification
- The 250 ms ceiling stays provisional and unvalidated until a named product or security owner approves the requirement and its rationale. **Owner: not yet named.**
- Qualifying staging host: `audspecterver` (the existing staging host, `zain@audspecterver`, per the deployment record). Before use, confirm it is not carrying other load during qualification. Record its hardware, OS and build, Go version, CPU and memory, workload, and background load.
- Until qualified: no timing-based PASS or FAIL verdict and no new timing scenarios. Timing is reported as diagnostic only, or INCONCLUSIVE when qualification is missing.

## Design: field-level disclosure evidence for NBFC-007 (DATA-102)

Status: **approved 4 November 2026 with the conditions below. Implementation follows.**

### Current behaviour

- The access event (`lab/access.go`, `accessEvent`) records the action, action class, actor role, owners, outcome, status and identity. It records nothing about which fields a response returned.
- `detect.Event` mirrors that. REL-008 (`sensitiveProjection`) matches only the action suffix `/statement`, `/card`, `/audit` or `/view` on a foreign-owned object. A loan read with `?expand=kyc` matches none of these.
- Vulnerable build, `GET /api/nbfc/loans/{id}?expand=kyc` (`nbfcGetLoan`): returns the borrower's KYC record with `pan_number` and `aadhaar_ref` to any caller. The fixed build never returns KYC through the loan read.
- DATA-102's baseline reads the owner's own loan, so the attacker-owned KYC record is the same owner's record. Ownership rules (REL-004, REL-008) cannot fire: the caller owns what they receive. The violation is the kind of data disclosed through a non-KYC resource, not who owns it.

### Proposed change

1. **Disclosure classes, not values.** Each protected field carries a fixed classification in the fixture's pack policy. For NBFC: `pan_number` and `aadhaar_ref` are `kyc_identity`; `debit_mandate` is `payment_credential`; `disbursement_account` is `account_identifier`. Classes are a closed set defined in code, never taken from a request.
2. **Response-side holder.** Reuse the `responseOwners` pattern (`lab/response_owners.go`): a per-request holder that a handler fills when it writes a protected field into a response. The holder records only the class and the field name. A helper, for example `noteDisclosure(r, class, field)`, is called at the point the field is added to the body, so the event reflects what was sent, not what the record contains.
3. **New optional event fields**, both `omitempty`:
   - `disclosed_classes []string`: the distinct classes in the response.
   - `disclosed_fields []string`: the field names, from the same closed set. For example `["pan_number","aadhaar_ref"]`.

   Neither field holds a value. Field names come from the fixture policy, so they can't carry request text.
4. **Detection rule REL-020 (next free ID; confirm before implementation).** Fires when `disclosed_classes` contains `kyc_identity` and the action is not on the KYC resource (`/api/nbfc/kyc/`). It does not depend on ownership, so the owner's own expanded read is still detected. It is the policy violation: identity evidence leaves through a loan projection.
5. **No change** to existing rules, to `ObjectOwner` or `ObjectOwners`, or to any existing field's meaning.

### Expected verdicts

| Build | Request | Expected event | REL-020 |
|---|---|---|---|
| Vulnerable | owner reads own loan with `?expand=kyc` | `disclosed_classes=["kyc_identity"]`, `disclosed_fields=["pan_number","aadhaar_ref"]` | fires |
| Fixed | same request | no disclosure fields (the KYC is not returned) | does not fire |
| Vulnerable | owner reads own loan without expand | no `kyc_identity` class | does not fire |
| Vulnerable | owner reads own KYC on `/api/nbfc/kyc/` | `kyc_identity` but on the KYC resource | does not fire |

The DATA-102 assertion changes from `not_evaluated` to `fixture_validated` with reason, after the tests pass. The detection table gets an `APIBAS-REL-020` expectation: vulnerable detected, fixed not detected, repeated runs identical.

### Security implications

- No protected value enters the event, the detection store or any result. Tests assert that the serialised event does not contain `BAS-SIM-PAN-A` or `BAS-SIM-AADHAAR-A`.
- The class set is closed. An unknown field name is recorded as `unclassified` and the handler test fails, so a new protected field cannot silently skip classification.
- The holder records what was written, so a future change that adds a field to the response without calling `noteDisclosure` is caught by the drift test below.

### Migration and compatibility

- No database change. Events are in-memory in the lab today. The results store (the planned next step) must keep the same shape: classes and field names only.
- Existing event consumers ignore unknown JSON fields. A golden test asserts that an event with no disclosure serialises byte-identical to today.
- The Elastic-style fixture events in the detection tables have no disclosure fields, so existing expectations do not move.
- Live SIEM: this is a fixture contract. Whether the production event source can carry the same fields is an open question, and live validation remains not done.

### Tests

1. `detect`: REL-020 fires on `kyc_identity` outside `/api/nbfc/kyc/`; does not fire on the KYC resource, on other classes, or with no classes; fires for the owner.
2. `lab`: vulnerable expand event carries the expected classes and field names; fixed build carries none; the serialised event contains no protected value.
3. `lab` drift: every protected field in the NBFC fixture has a classification. A new protected field with no class fails the test.
4. `runner` phase34 table: REL-020 expectation for DATA-102, vulnerable detected, fixed not detected, repeatability check.
5. `runner` scenario: DATA-102 still FAILs exploited on vulnerable and PASSes on fixed (exploitability is unchanged; detection is separate).
6. Golden JSON: event without disclosure is byte-identical to the current format.

### Decision needed

- Approve the class set and the rule ID (REL-020).
- Confirm that a policy-based rule (class on a non-owning resource) is acceptable alongside the existing owner-based rules.

No code will be written until this design is approved.

### Approval conditions (4 November 2026)

1. **Values.** The event records field names and disclosure classes only. No actual values, no partial PAN or Aadhaar, no reversible representation.
2. **Emitted, not intended.** REL-020 evaluates the response as it is written. The handler records a field only when the field is present in the body that is serialised. Classes are found by walking the final body, recursively, so a nested `kyc` object is covered and a field that was built but not emitted is not recorded.
3. **Explicit allowlist.** Every class has an explicit list of resources where it may appear. A class on any other resource is a REL-020 event. Nothing is allowed by default.

   | Class | Allowed resource (path) |
   |---|---|
   | `kyc_identity` | `/api/nbfc/kyc/`, `/api/nbfc/admin/kyc/` |
   | `payment_credential` | `/statement` (the owner's statement) |
   | `account_identifier` | the loan resource: `/api/nbfc/loans/{id}` and `/api/nbfc/admin/loans/{id}` is **not** allowed |

   Resource is derived from the action path, using the same path rules the lab uses.
4. **Negative test.** Legitimate KYC-resource disclosure (the owner reads their own KYC record through `/api/nbfc/kyc/`) must not trigger REL-020. It is part of the test set below.
5. **Ownership rules unchanged.** REL-004, REL-007, REL-008 and the other existing rules keep their logic. Exploitability and detection are reported separately in the results.

### Consequence to check before merging

`account_identifier` on the admin loan route is not allowed. The vulnerable admin route returns `disbursement_account` to a borrower (AUTHZ-106 vulnerable), so REL-020 will also fire there. That is a true policy violation, but it is an extra detection on a scenario whose declared expectation is REL-019, REL-007 and REL-004. The detection table must state this explicitly, not hide it.

## Implementation: NBFC-007 disclosure detection (REL-020), 4 November 2026

Implements the approved design above. Exploitability and detection are reported separately.

### Changes

- `detect/disclosure.go` (new): closed class set (`kyc_identity`, `payment_credential`, `account_identifier`); the explicit resource allowlist (`kyc` for kyc_identity; `statement` for payment_credential; `loan` for account_identifier). Nothing is allowed by default. Resource is derived from the action path. Admin KYC is in the KYC family; the admin loan route is its own resource, so an account identifier there is outside the policy.
- `detect/detect.go`: `Event.DisclosedClasses` and `Event.DisclosedFields` (both optional, `omitempty`); REL-020 appended to `ElasticRules`. The ownership rules are unchanged.
- `lab/disclosure.go` (new): field-to-class map (`pan_number`, `aadhaar_ref` to kyc_identity; `debit_mandate` to payment_credential; `disbursement_account` to account_identifier). `emittedDisclosureFields` walks the response body as it is serialised, recursively, and returns field names only. `writeNBFCJSON` records those names on the request holder, then writes the same value.
- `lab/response_owners.go`: the per-request holder gains `disclosed` and `noteDisclosedFields`.
- `lab/access.go`: `accessEvent` gains the two fields; `logAccess` fills them from the holder.
- `lab/nbfc.go`: all 28 NBFC response writes go through `writeNBFCJSON`, except the audit log route, which holds no protected field. **Behaviour change in the fixed build:** the statement's loan object now returns public fields only (`statementLoanBody`). Before, the owner's statement carried `disbursement_account`, which the policy does not allow on the statement. The owner still receives the debit mandates the statement is for. The vulnerable build is unchanged.
- Catalogue (generator-produced): DATA-102 detection moves from `not_evaluated` to `fixture_validated` with primary REL-020. AUTHZ-106 declares REL-020 as an additional rule. DATA-104 declares REL-020 as an additional rule.
- `runner/phase34_detection_test.go`: REL-020 expectation. Vulnerable detected on the expanded loan read, the admin loan route and the statement; fixed not detected on any.

### Tests

- `detect/disclosure_test.go`: the policy matrix (allowed and disallowed combinations, unknown class), no-disclosure event, and REL-004 unchanged for the owner's own KYC read.
- `lab/disclosure_test.go`: drift test (every protected fixture field has a class), nested walk and names-only result, class derivation, empty disclosure omitted from the event JSON.
- `runner/phase8_disclosure_test.go` (end to end, events decoded the way the runner decodes them):
  - vulnerable expanded loan read records KYC names and classes, REL-020 fires, and no protected value appears in the serialised events;
  - fixed expanded loan read emits no KYC;
  - **negative test (approved condition):** the owner's KYC read through `/api/nbfc/kyc/` records kyc_identity and REL-020 does not fire;
  - fixed statement omits the disbursement account and keeps the debit mandate;
  - vulnerable admin loan records account_identifier and REL-020 fires.

### Results

- **Exploitability (unchanged):** `TestPhase7_NBFCScenariosBothBuilds` passes. All ten NBFC scenarios still FAIL exploited on the vulnerable build and PASS on the fixed build. No scenario verdict changed.
- **Detection:** `TestPhase34_DetectionMatchesDeclaredExpectations` passes across the full catalogue, in both builds, with extraction on and off, and repeated twice. DATA-102: vulnerable REL-020 detected, fixed not detected. AUTHZ-106 and DATA-104: REL-020 detected on the vulnerable build only, as an additional rule.
- Full apibas suite (`go test ./internal/apibas/... -count=1 -timeout 60m`): EXIT 0. Runner package about 9.5 minutes.

### Notes for review

- **Two additional detections were not in the original declarations.** AUTHZ-106 and DATA-104 vulnerable builds now also raise REL-020. Both are true policy violations (an account identifier and a disbursement account reach a non-loan resource), and both are declared now rather than left hidden.
- **Admin KYC is in the KYC family.** The vulnerable admin KYC route returns identity evidence to a caller. That is an authorisation failure, which REL-019 and the administrative scenarios cover. REL-020 does not add a second verdict for it.
- **The fixed statement change** is the one behaviour change to a fixed build. It follows the approved policy and was not in the design text, so it is called out here.
- **Stated gap:** fixture-validated only. Whether a production event source can carry the same disclosure fields is an open question, and live validation is still not done.
- `docs/detection-rules-coverage.md` shows a modified Elastic count from another session's rule-library work. It is not part of this change and was not staged.

## Design: identity attribution for AUTHN-003 and AUTHN-007

Status: **proposed. No code changes until approved.**

### Current behaviour (lab, `lab/lab.go`, `lab/tls.go`, `lab/access.go`)

- **Claimed identity (`identify`).** Resolved from, in order: an unsigned token's subject (vulnerable build only); the signed token's customer; the `X-Customer-Id` header, which the vulnerable build trusts over the token. Logged as `identity`.
- **Verified identity (`verifiedIdentity`).** The customer a signed token proves, or the common name of a client certificate that chains to the lab CA. Only when no `Authorization` header is sent. Logged as `verified_identity`.
- **Certificate without credentials.** When `identify` reports "missing", the access log falls back to the presented certificate's common name **without chain verification**. This value becomes `identity` in both builds, even when the chain check fails and the fixed build returns 401.
- **REL-013.** Fires when `identity` is a customer and `verified_identity` differs, on a 2xx response. It covers AUTHN-003 (unsigned subject) and AUTHN-007 (self-signed certificate), and both declare it.

### Gaps that remain

1. **Event meaning is inconsistent for certificates.** The access log records an unverified common name as `identity`. The contract says `identity` is "the claimed identity the verifier accepted". For a certificate that did not chain, no verifier accepted it.
2. **No basis.** Consumers cannot tell whether `identity` came from a signed token, a chain-verified certificate, an unsigned claim, a header or an unverified certificate.
3. **Precedence edge.** A valid chain-verified certificate is ignored as `verified_identity` when a malformed `Authorization` header is also sent. The request is then judged as an unproven claim.
4. **Identity-keyed rules read the claim.** REL-004, REL-010 and the owner comparisons use `identity`. They are correct for the planted weakness because REL-013 carries the signal, but they do not state which source they trusted.

### Proposed change

1. **One resolution point.** Replace the separate calls with a single `resolveAuth(r)` that returns `{Identity, Basis, Verified, Claimed}`. `identify`, `verifiedIdentity` and the access log all read from it, so the event cannot disagree with the identity that served the request.
2. **Basis field (additive).** New optional event field `identity_basis`, one of `signed_token`, `chain_verified_cert`, `unsigned_token_claim`, `header_claim`, `unverified_cert_claim`. Omitted when the request carries no credential.
3. **Claim field (additive).** New optional `claimed_identity`, set only when the claim is not proven (`unsigned_token_claim`, `header_claim`, `unverified_cert_claim`).
4. **`identity` keeps its current value.** For an unverified certificate it stays the common name. Changing it to empty would stop REL-013 firing on AUTHN-007, so the value is kept and the basis explains it.
5. **Precedence fix.** A chain-verified certificate is recorded as verified when the `Authorization` header is absent or unparseable. A valid signed token still wins over a certificate.
6. **Rules unchanged.** REL-013 and the other rules keep their logic. No new rule is proposed in this step. A later step may make REL-013 read `identity_basis` directly; that is a separate change.

### Security implications

- The lab never uses a header or an unverified certificate for access. The planted weaknesses stay exactly where they are: the vulnerable build still honours `X-Customer-Id`, the unsigned subject and the certificate common name in the mTLS handler.
- `claimed_identity` holds identity names only. No token, key or certificate material is recorded.
- This changes what the lab records, not what the product does. The orchestrator's own authentication path (`internal/api`) is out of scope and needs its own review; this design does not claim anything about it.

### Migration and compatibility

- Both new fields are optional and omitted when empty. Existing consumers ignore unknown JSON keys.
- `identity` and `verified_identity` keep their values for every request. The only change is that the basis and claim are added beside them.
- No database change. The results store, when built, stores the basis as recorded.
- Acceptance is verdict stability: the full detection table, the exploitability tests and REL-013 must give the same results before and after.

### Tests

1. Table test for `resolveAuth`: valid signed token; revoked token; unsigned subject (vulnerable and fixed); `X-Customer-Id` with a valid token (vulnerable and fixed); chain-verified certificate; self-signed certificate; malformed `Authorization` with a valid certificate; no credential.
2. Event tests: each case records the expected `identity_basis` and `claimed_identity`; the self-signed certificate records `unverified_cert_claim` with `identity` unchanged.
3. Compatibility: every pre-existing event key keeps its value for the existing scenarios, and empty fields are omitted.
4. Verdict stability: AUTHN-003 and AUTHN-007 still FAIL exploited on the vulnerable build and PASS on the fixed build, and REL-013 still fires on both vulnerable builds and not on the fixed builds. The full detection table is unchanged.

### Decisions needed

- Approve the two additive fields and their names.
- Approve keeping `identity` unchanged for unverified certificates.
- Confirm that the orchestrator's own authentication attribution is a separate item.

No code will be written until this design is approved.

## Implementation: identity attribution (AUTHN-003, AUTHN-007), 4 November 2026

Implements the approved design above.

### Changes

- `lab/auth_context.go` (new): `resolveAuth` is the single source for the access event's identity, basis and claim. It mirrors `identify`, so `identity` keeps its value. New basis constants: `signed_token`, `chain_verified_cert`, `unsigned_token_claim`, `header_claim`, `unverified_cert_claim`.
- `lab/lab.go`: `verifiedIdentity` now uses a chain-verified certificate whenever the `Authorization` header is not a Bearer credential. Before, it ignored a certificate when the header was present but malformed. A valid signed token still wins, and an unknown Bearer token is still not replaced by a certificate.
- `lab/access.go`: `accessEvent` gains `identity_basis` and `claimed_identity` (both `omitempty`). `logAccess` takes its identity from `resolveAuth`. The identity values are the same as before.
- `detect/detect.go`: `Event` mirrors the two fields so the runner decodes them. No rule reads them yet, so no verdict depends on them.

### Tests

- `lab/auth_context_test.go`: 11 cases with real certificates from the lab PKI and a self-signed certificate: signed token, unsigned subject (vulnerable and fixed), header claim (vulnerable and fixed), revoked or unknown token, no credential, chain-verified certificate, self-signed certificate, malformed header with a verified certificate, unknown Bearer with a verified certificate. Each checks identity, basis, claim and verified identity. Plus: empty identity fields are omitted from the JSON.
- `runner/phase8_identity_test.go`: end to end through the request path, with events decoded as the runner decodes them.
  - AUTHN-003 vulnerable: `unsigned_token_claim`, claim `cust-b`, verified empty, REL-013 fires.
  - AUTHN-003 fixed: refused, no basis, REL-013 does not fire.
  - Header claim (vulnerable): `header_claim`, claim `cust-b`, verified `cust-a`, REL-013 fires.
  - Signed token: `signed_token`, no claim, REL-013 does not fire.

### Results

- **Exploitability:** unchanged. AUTHN-003 and AUTHN-007 keep their verdicts.
- **Detection:** REL-013 unchanged in every case where it fired before. `TestPhase34_DetectionMatchesDeclaredExpectations` passes across the catalogue, both builds, extraction on and off, repeated twice.
- Full apibas suite: all packages pass except one timing test (see below).
- **Timing flake:** `TestABUSE002Repeatability` reported `ATTACK_MEASUREMENT_INVALID` once, under the full suite's parallel load. Run alone, it passed twice (281 s and 287 s). The timing policy already treats this scenario as provisional, and its result is diagnostic. This is noted, not hidden. The rest of the runner package passed in that run.

### Notes for review

- `identity` deliberately keeps the unverified certificate's common name. Clearing it would stop REL-013 firing on AUTHN-007, which is why the basis carries the meaning instead.
- The precedence change affects only `verified_identity`, and only when a malformed header is sent alongside a verified certificate. In that case `identity` is `unknown`, so REL-013 cannot fire on it either way.
- Stated gap: the orchestrator's own authentication path (`internal/api`) is not covered by this change, as the design said.

## Design: plaintext credential columns (D4), inventory and bounded remediation

Status: **proposed, inventory complete. No code changes until approved.** Scope is the orchestrator's own Postgres. The agent's proxy and database credentials are already held on the agent (see Precedents) and are not in scope.

### Inventory: credential values stored as plaintext text in the orchestrator database

| Table (`internal/db/postgres.go`) | Columns | Consumers (non-test) | API response |
|---|---|---|---|
| `siem_configs` | `token`, `password`, `client_secret` | `api/siem_handlers.go`, SIEM correlation | list omits them; update preserves `***` |
| `detection_connectors` | `client_secret`, `api_token` | `api/detectverify_handlers.go`, `detectverify/elastic.go` | response carries `hasClientSecret` and `hasApiToken` |
| `action_connectors` | `client_secret`, `api_token` | `api/action_handlers.go`, response connector clients | **to verify**: the GET path was not confirmed |
| `threat_intel_config` | `api_key` | `api/threat_intel_config_handlers.go`, `connector/otx.go`, `ioc/otx.go` | **to verify**: request body confirmed, GET not confirmed |
| `openaev_config` | `bearer_token` | `api/openaev_handlers.go` | **to verify**: request body confirmed, GET not confirmed |
| `taxii_connector_config` | `password`, `client_cert`, `client_key` | `taxii/store.go`, `api/taxii_handlers.go` | returns `hasPassword`, `hasClientCert`, `hasClientKey` only |
| `sso_configs` | `client_secret` | `api/sso_handlers.go`, `api/sso_login_handlers.go` | masked, never returned |
| `notification_webhooks` | `secret` | `notifications/store.go`, `api/notification_handlers.go` | returns `***` when set |

Not in scope, and already safe:
- `users.password_hash`, `agent_enrollment_tokens.token_hash`, and agent certificates: stored as hashes.
- `dlp_sink_tokens.token`: a bearer-style token stored as plaintext. It is run-scoped and expires, so it is lower risk. It is listed here as a separate decision, not included in the eight tables.
- `dbsim_targets.credential_ref`: a reference, not a secret. This is the pattern this design follows.

### Existing precedents

- **Database credentials (dbsim).** Targets store only `dbcred:<name>` references. The agent resolves a reference locally: a `BAS_DBCRED_<NAME>` environment variable, otherwise a DPAPI-protected value (Windows) or a root-owned, mode-0600 file (Linux). An unresolvable reference is a refusal, never a fallback to a default account.
- **Proxy credentials.** Held agent-side with DPAPI on Windows, per the same note in `agent/dbcred.go`.

So the platform already has a reference-based design and an agent-local protected store. None of those secrets sits in the orchestrator database.

### Current behaviour

- Every value in the table above is a plaintext `text` column. The only protection is the disk-level encryption the schema comment assumes (TDE or LUKS).
- `pgcrypto` is created at startup and never used for these columns.
- The API already avoids returning most values, using `has*` booleans or `***`. That protects responses. It does not protect the database, its dumps, or its backups.
- Backups (`backup_jobs`, and the upgrade backup) contain the same plaintext, so every archive taken so far holds the values.

### Proposed change: references in the database, values in a secret store

1. **Secret store interface.** The orchestrator gets a `SecretStore` with `Put(ref, value)`, `Get(ref)` and `Delete(ref)`. The backend is the one chosen under D1 (Vault, or another approved manager). It follows the `dbcred:` pattern: a reference is an opaque name, and the value never enters a row, an event, a log or a response.
2. **Per-table reference column.** Each affected table gets `<column>_ref text`. New writes store the value in the store and the reference in the row. Reads resolve the reference only at the point of use: SIEM correlation, connector call, webhook send, TAXII poll, SSO login.
3. **Migration in three phases, one connector at a time.**
   - Phase 1: add the reference columns and dual-read (prefer the reference, fall back to the plaintext column).
   - Phase 2: a one-time job moves each plaintext value into the store, writes its reference, and clears the plaintext column.
   - Phase 3, a later release: drop the plaintext columns. This waits until the backup and restore plan below is proven.
4. **Scope bounded to these eight tables.** No change to the users, enrollment or certificate tables, and no change to the agent.
5. **Preserve the API contract.** `***` still means "keep the stored value" on update, and the `has*` booleans keep their meaning. The UI sees no change.

### Alternative if D1 approves no external store

Keep the values in Postgres, but encrypt them at the column with `pgcrypto` (`pgp_sym_encrypt`), with the key in a root-only file outside the database and outside its dumps, loaded at startup. This is weaker than a secret store: the key sits on the same host, so an attacker with the orchestrator process can read it. It is an acceptable interim only if the residual risk is stated in the QA log.

### Security implications

- Plaintext in backups is the largest exposure today. After migration, a new backup holds references only. Old archives keep their plaintext until they are deleted or re-taken, so the values in them must be treated as exposed (see D5).
- Resolution happens at use, inside the call that needs the value. A value must never be logged, put in an access event, or returned. Tests check each of these.
- The secret store becomes a critical dependency. Its availability and its access audit become part of the platform's security surface.

### Migration and compatibility impact

- **Schema:** additive first (`*_ref` columns), then the plaintext columns are dropped in a later migration. Each phase is a separate migration with a tested rollback to the previous phase.
- **Backup and restore:** the secret store must be backed up and restored with the database. A restored database holding references, without the store's contents, cannot reach its connectors. The restore procedure must say so, and the upgrade path (`install.sh --upgrade`) must carry the store's contents, in the same way it carries the CA key.
- **Existing installs:** the migration job runs once and is idempotent. A value that cannot be moved is reported, never silently dropped.
- **Connectors:** a connector whose reference cannot be resolved is refused with a clear error, never silently skipped. Dual-read means a row created before the migration keeps working until the job moves it.

### Tests

1. Round trip per table: a written value is resolved for the connector call, and the row holds only the reference.
2. No plaintext after migration: a sentinel value written before migration must be absent from every credential column afterwards.
3. No secret in output: the sentinel must not appear in any API response, access event, log line or error message.
4. The `***` update path keeps the stored value, and the `has*` booleans are unchanged.
5. Idempotent migration: running the job twice changes nothing the second time.
6. Refusal on an unresolvable reference, with no fallback to a default value.
7. Backup and restore: a restored database resolves its references from the restored store, and a restore without the store fails loudly.

### Decisions needed

- **D1:** the secret store (Vault or another approved manager), or the `pgcrypto` interim.
- **D4 scope:** approve the eight tables and the three phases. Decide separately on `dlp_sink_tokens`.
- **D5, linked:** rotation of every credential that was stored in plaintext, since old backups hold it. Rotation was declined earlier (P0). The exposure analysis here is the reason to revisit it.
- **Backup and restore owner:** who owns the store's backup, and who runs the restore test.

### Unverified items

- The GET responses of `action_connectors`, `threat_intel_config` and `openaev_config`. The request side is confirmed. The response side must be read before the migration starts, because a leak there would be a separate defect.

No code will be written until this design is approved.

## D4 decisions and pre-implementation checks (4 November 2026)

Decisions approved by the product owner:
- **D1, secret store:** prefer an approved external manager if it can be operated on on-prem and air-gapped installs. Otherwise the `pgcrypto` interim, with the conditions below. Do not build two interchangeable store implementations.
- **D4, scope:** the eight inventoried tables, three-phase migration (add reference columns with dual-read; migrate values and verify resolution; drop plaintext columns in a later release after compatibility and rollback criteria pass). `***` update behaviour and the API contract are unchanged. `dlp_sink_tokens` is a separate decision.
- **D5, rotation:** treat credentials in historical plaintext backups as potentially exposed. Rotate all affected credentials after migration, in this order: (1) SSO client secret and webhook signing secret; (2) SIEM, detection/response and threat-intelligence credentials; (3) OpenAEV and TAXII credentials, including client certificate and key material. Each rotation verifies the new credential works and the old one is revoked or invalidated. Historical backups are not deleted as a substitute.
- **D4 backup and restore:** a named operational owner is required before production rollout (see Open items).

### Interim conditions if `pgcrypto` is used

- The key is stored outside PostgreSQL, in a root-only file.
- The key is never stored in the database, in database dumps, or in backup archives.
- Strict file permissions, and a documented recovery procedure.
- Residual risk, stated explicitly: compromise of the host and the key can expose every encrypted credential.

### Pre-implementation checks

1. **External secret manager availability: not confirmed.** The repository has no client for Vault, AWS Secrets Manager or any other external manager. The secret rotation runbook lists Vault as a future option ("move all runtime secrets to env vars / a secrets manager"). The air-gap capability list does not name one. Whether an external manager can be operated on the target on-prem and air-gapped installs is a fact about the customer environment. It must be confirmed by the product owner before the store is chosen.
2. **Unverified GET responses: verified, none exposes a credential.**
   - `GET /api/threat-intel/{connector}/config`: selects `base_url, enabled, insecure_tls, last_sync_status, last_error`. `api_key` is not returned.
   - `GET /api/openaev/config`: selects `base_url, poll_interval_hours, enabled, last_sync_status, last_error` and timestamps. `bearer_token` is not returned.
   - `GET /api/actions/configs` (the only read route for action connectors): selects `id, name, provider, enabled, tenant_id, base_url, kill_process_script_name` and timestamps. `client_secret` and `api_token` are not returned. The update handler returns a status only.
   No separate API defect is raised from these three.
3. **Backup and restore owner: not named.** This must be named before production rollout.

### New finding: the automatic upgrade backup captures the interim key's likely location

- `install.sh --upgrade` takes an automatic backup that includes `<DATA_DIR>/.env` and `<DATA_DIR>/pki/` (`packaging/compose/install.sh`, around line 1408; `docs/guides/backup-restore.md`).
- If the `pgcrypto` interim is chosen, the key must not sit under `<DATA_DIR>` or in any file the upgrade backup copies. Otherwise every upgrade archive would hold the key next to the encrypted credentials, which breaks condition 2 above.
- Options for the owner to decide: store the key outside `<DATA_DIR>` (for example, a separate root-only path that the installer creates and excludes from backups, with its own documented recovery copy), or make the upgrade backup exclude the key file explicitly and test that exclusion.

### Status

- Implementation is **not started**. It waits on pre-implementation items 1 and 3, and on the decision about where the interim key lives if the interim is chosen.
- Nothing in the database or the code has changed by this decision.

## D4 phase 1: secret store interface, pgcrypto interim, reference columns (4 November 2026)

### Decisions recorded

- **D1, secret store:** an external secret manager is **assumed unavailable** for the current on-prem and air-gapped baseline. The `pgcrypto` interim is used. Vault is not a deployment prerequisite. The store interface is kept compatible with a future Vault backend.
- **Interim key:** stored outside PostgreSQL, in a root-owned file, default `/etc/audspect/secrets/db-encryption.key`. Access is restricted to the Audspect service account and root. The key is excluded from database dumps and ordinary backups, and backed up separately through an encrypted, access-controlled recovery process.
- **Residual risk (stated):** compromise of the host and the key together exposes every encrypted credential.
- **D4, scope:** the eight tables, three phases, as approved. `dlp_sink_tokens` is separate.
- **D5, rotation:** after migration, in this order: (1) SSO client secret and webhook signing secret; (2) SIEM, detection/response and threat-intelligence credentials; (3) OpenAEV and TAXII credentials, including certificate and key material. Each rotation verifies the new credential and invalidates the old one. Historical backups are not deleted as a substitute.
- **Backup and restore owner:** the Admin role (the product owner who approved this decision). A named individual is not recorded here.

### Pre-implementation items: status

1. External manager availability: settled by the decision above (assumed unavailable).
2. Unverified GET responses: verified safe (see the previous section).
3. Backup and restore owner: Admin role recorded above.

### Built in phase 1

- `internal/secretstore/store.go`: the `Store` interface (`Put`, `Get`, `Delete`), the reference grammar (`cred:<table>:<row>:<column>`), `ErrNotFound`, `ErrBadRef`, `ErrEmptyValue`. Values never appear in an error.
- `internal/secretstore/pgcrypto.go`: `PGStore`. Values are encrypted with `pgp_sym_encrypt` into `credential_secrets`, which holds ciphertext only. The key is passed per statement and never written to the database. A wrong key is an error, never a wrong value.
- `internal/secretstore/keyfile.go`: `LoadKeyFile`. The file must hold the base64 of exactly 32 random bytes on one line. On Linux and macOS (`keyfile_unix.go`) it must be owned by root and carry no group or other bits. Windows (`keyfile_other.go`) applies the format check only, because Windows ACLs are not expressed in mode bits.
- `internal/db/secretstore_schema.go`: `EnsureSecretStoreSchema` creates `credential_secrets` and adds `<column>_ref text NOT NULL DEFAULT ''` to the fourteen credential columns in the eight tables. It is idempotent and runs at server startup, beside the other schema steps (`cmd/server/main.go`).

### Tests and results

- Unit (`go test ./internal/secretstore/`): reference grammar, reference construction, permission-bit checks, key format (short, non-base64, empty, two lines, missing). All pass.
- Database, against the Postgres 16 test container: round trip; the stored column does not contain the plaintext; overwrite and delete; missing reference is `ErrNotFound`; a wrong key returns an error with no key or value in the text; empty value and malformed reference are refused. All pass (`internal/secretstore`, 80 s).
- Schema (`internal/db`, `TestEnsureSecretStoreSchemaAddsReferenceColumns`): all fourteen reference columns present as NOT NULL text, the step run twice, the table present. Passes.
- Linux build, Windows cross-compile of `cmd/server`, `cmd/apibas-lab` and `cmd/apibas-runner`: pass.

### Not done in phase 1 (stated)

- **No connector reads or writes the reference columns yet.** Runtime behaviour is unchanged. Dual-read in the consumers (SIEM, detection and response connectors, threat intel, OpenAEV, TAXII, SSO, webhooks) is the next step, followed by the migration job (phase 2). Phase 3, dropping the plaintext columns, follows after compatibility, rollback, backup recovery and rotation have all passed verification.
- **Installer provisioning is not done.** `install.sh` does not yet create `/etc/audspect/secrets/db-encryption.key` (root-owned, 0600), does not place it in the container, and does not set the service account's access. Deployment must not reach production before this exists. The key is not under `<DATA_DIR>`, so the automatic upgrade backup (which copies `.env` and `pki/`) does not capture it, but this must be confirmed by test.
- **Backup exclusion and separate recovery copy** of the key are not implemented.
- **Restore test** (every database reference resolves after restore) is not run.
- **Rotation** (D5) has not started. It waits for migration.

## D4 phase 1a: installer provisioning of the interim encryption key (4 November 2026)

### Design
- Key location: `/etc/audspect/secrets/db-encryption.key`, directory `/etc/audspect/secrets` (root:65532, 0750). Outside DATA_DIR, so the upgrade backup (which copies `.env` and `pki/`) and database dumps do not capture it.
- Ownership: root owns the file and the directory. Group 65532 is the orchestrator container's own GID (`USER nonroot`, UID/GID 65532), so the container reads the key through its primary group. No compose `group_add` is needed. Mode 0640. Nothing else has access.
- Loader check changed to match: owner must be root, and the mode may give the group read but no group write or execute and nothing to others (mask 0o037). Previously the check forbade all group bits, which the container could not satisfy.
- Fresh install (`mode_install`, step 3): generate the key when absent; reuse and verify it when present; repair owner and mode when they have drifted; refuse a key whose content is not base64 of 32 bytes (left unchanged).
- Upgrade (`mode_upgrade`, before any change): verify the key. A missing key stops the upgrade with a pointer to `--import-db-key`. An upgrade never generates a key, because a new key would make every stored credential unreadable.
- Recovery: `install.sh --export-db-key <file>` writes an AES-256-CBC copy with PBKDF2 (600,000 iterations) under an operator passphrase (at least 12 characters, entered twice). `install.sh --import-db-key <file>` restores it, refuses to replace an existing key, and writes nothing on a wrong passphrase. The passphrase is read interactively; `BAS_DB_KEY_PASSPHRASE` exists for automation only.
- Uninstall: `mode_uninstall` removes only DATA_DIR, so the key in `/etc` survives an uninstall. Recovering data after a reinstall therefore needs the key still present or imported.

### Changes
- `packaging/compose/db-encryption-key.sh` (new): sourced by `install.sh`; functions only.
- `packaging/compose/install.sh`: sources the helper; `--export-db-key` and `--import-db-key` arguments; provisioning in fresh install step 3; verification in upgrade; dispatch. Diff is 15 insertions.
- `packaging/compose/tests/db_encryption_key_test.sh` (new): 11 cases.
- `orchestrator/internal/secretstore/keyfile.go` and `store_test.go`: mode check relaxed as above; `DefaultKeyPath` comment corrected to 0640.

### Tests and results
- `tests/db_encryption_key_test.sh` in `debian:stable-slim` as root: 11 passed, 0 failed, mode bits enforced.
- The same suite as UID 1000 (`setpriv`): 11 passed, 0 failed.
- Earlier run on NTFS under Git Bash failed on the mode check, as intended: NTFS reports 644 regardless of chmod, so the check does not hold there. The suite now detects enforcement and skips mode-only cases when it is absent, reporting them as skipped, never passed. Run the suite on Linux.
- `packaging/compose/setup-install-state.test.sh` in Linux: all tests pass (unchanged behaviour).
- `go test ./internal/secretstore/` for the mode and format cases: pass.

### Not done (stated)
- The orchestrator does not load the key yet. `LoadKeyFile` has no production caller. Wiring it into the server, and mounting `/etc/audspect/secrets` read-only into the container, belong to the connector dual-read step, so nothing reads the key until then.
- The backup exclusion is true by construction (the key is outside DATA_DIR). It is not yet covered by a test that runs `install.sh --backup` and inspects the archive.
- Not run on a real installed host. Real `install.sh --install` needs Docker and images; not run here.
- Recovery copy off-host and its passphrase custody are owned by the Admin role; not verified by this phase.

## D4 phase 1b: dual-read design and core (4 November 2026)

### Design (approved: fail closed)
- **Current behaviour:** connectors read plaintext columns (`siem_configs.token`, `openaev_config.bearer_token`, and the other twelve). Reference columns are empty, so nothing reads them.
- **Proposed read path:** every credential read goes through `secretstore.Resolve(ctx, store, ref, plaintext)`.
  - `ref` empty: return plaintext. This is every row until phase 2 migrates it, so runtime behaviour is unchanged.
  - `ref` set: return the stored value. A missing store returns `ErrUnavailable`. A missing or undecryptable value returns its error. **The plaintext column is never used once a reference exists.** A stale plaintext after rotation would otherwise be used silently.
- **Writes:** unchanged in phase 1 and 2 (plaintext continues). Phase 2 writes the reference and verifies it resolves.
- **Key wiring:** startup validates the key with `LoadKeyFile(DefaultKeyPath)` and logs verified or warns. A missing or invalid key does not stop the server, because plaintext rows still work; references then fail their own operation.
- **Container access:** `/etc/audspect/secrets` is mounted read-only into the orchestrator (`docker-compose.yml`). The key is readable by GID 65532, the container's own group.

### Changes
- `orchestrator/internal/secretstore/resolve.go`: `Resolve`, `ErrUnavailable`.
- `orchestrator/internal/secretstore/resolve_test.go`: plaintext when empty; store value (not the plaintext) when set; fail closed with no store; fail closed on a missing value; malformed reference refused.
- `orchestrator/cmd/server/main.go`: key check at boot after the secret store schema.
- `packaging/compose/docker-compose.yml`: read-only secrets mount.

### Tests and results
- `go test ./internal/secretstore/` (full package, Postgres test container): pass, 111 s. Includes the resolver tests and the existing round-trip, wrong-key and reference tests.
- `go build ./cmd/server`: pass. `GOOS=windows go build` for `cmd/server`, `cmd/apibas-lab` and `cmd/apibas-runner`: pass. `go vet ./internal/secretstore/`: clean.
- The compose mount is not exercised by a test. It must be checked on an installed Linux host.

### Not done (stated)
- **No consumer calls `Resolve` yet.** The fourteen read sites are unchanged. In phase 1, every reference is empty, so wiring the consumers changes nothing at runtime. Consumer wiring is the next step. It needs a store handle passed to each consumer, which the server does not hold yet.
- **The key is validated but not used** by any read. Nothing is encrypted with it until phase 2 writes references.
- **Phase 2 migration job** (move values, write references, verify resolution) is not started.
- Phase 3 (drop plaintext columns) and D5 rotation are not started.

## D4 phase 2a: dual-read in SIEM, detection and action connectors (4 November 2026)

### Scope
- Three consumers read credential references: SIEM (`siem_configs`: token, password, client_secret), detection verification (`detection_connectors`: client_secret, api_token), and response actions (`action_connectors`: client_secret, api_token). Each read selects the reference column beside the plaintext column and resolves through `secretstore.Resolve`.
- Not in this slice: OpenAEV, OTX/threat intel, SSO, notification webhooks, TAXII. They remain on plaintext reads.

### Behaviour
- Empty reference: plaintext, unchanged. Every row today, because phase 2 migration has not written references.
- Set reference: value from the store. Missing store, missing value or failed decryption returns an error. The plaintext column is never used as fallback.
- Masked-value preservation on update (`***`): the existing secret is read through the same resolver. A resolve failure returns HTTP 500 and writes nothing, so a stale plaintext is never written back.
- Store wiring: `cmd/server/main.go` opens the store with `secretstore.OpenStore(pool, DefaultKeyPath)` and passes it with `WithSecretStore`. On any failure the store is a true nil interface, not a typed nil pointer.

### Changes
- `internal/api/secrets.go` (new): `WithSecretStore`, `resolveCredential`.
- `internal/api/handlers.go`: `secrets` field.
- `internal/api/siem_handlers.go`, `detectverify_handlers.go`, `action_handlers.go`: refs selected and resolved in the update preservation reads and the loaders.
- `internal/secretstore/resolve.go`: `OpenStore`.
- `internal/api/secrets_test.go` (new): three database-backed tests. Each checks that a stored reference wins over a stale plaintext, that an unmigrated row returns its plaintext, and that a reference with no store fails.
- `internal/testutil/testdb.go`: adds `EnsureSecretStoreSchema` to the shared test bootstrap. Without it the reference columns do not exist in tests, and nine existing connector tests failed (found in the first full run, fixed here).

### Tests and results
- First full `internal/api` run: 10 failures and a 10-minute timeout panic. All failures were the missing reference columns in the test database, fixed by the bootstrap change. The timeout is Go's default, not a hang.
- After the fix: the nine previously failing tests and the three new tests pass (`-run` subset, 25 s).
- Full `internal/api` run with a 45-minute timeout (2561 s): one failure, `TestStopIsIdempotent` (`internal/api/aleef_handlers_test.go`, Aleef feature, not changed by this phase). All other tests in the package pass, including the three new credential tests and the nine connector tests fixed by the bootstrap change.
- The failing test sleeps a fixed 300 ms and then asserts the run has reached a halted state. Under the parallel load of the full suite that window can be missed. Run alone it passed 3 of 3 (`-count=3`). It also failed in the earlier full run before the bootstrap fix. Treated as a pre-existing timing flake in the Aleef test, not caused by this phase, and NOT hidden: the phase is committed with this failure on record. A timing fix to that test is a separate change.
- `go build` for `cmd/server`, `internal/api`, `internal/secretstore`: pass.

### Not done (stated)
- Writes still go to plaintext only. No reference is written yet, so the resolver path is exercised only by tests until phase 2 migration runs.
- Remaining consumers listed above.
- Phase 2 migration job, phase 3 column drop, D5 rotation: not started.

## API BAS assessment step 2: runner process contract, no database access (4 November 2026)

### Scope (approved order, step 2 of 6)
- Approved design: `docs/api-bas-assessment-design.md` (status APPROVED; acceptance requirements in section 5).
- This step covers the runner side only. The orchestrator job path (step 3) is not built yet.

### What changed
- `orchestrator/internal/apibas/runnerproto/runnerproto.go` (new): the contract. `JobRequest` (job ID, target, fixture, scenario IDs, allowed hosts, credentials file path) and `JobResult` (status, reports, reason). `DecodeJobRequest` refuses unknown fields and invalid values. `ValidateResult` is the orchestrator's gate: schema version, job ID, target, scenario set and report count, and each report's scenario ID and run tag. A failed result must carry a reason and no reports. A completed result must carry no reason. `LoadCredentials` refuses a file readable by group or others (Unix), and never echoes file content in errors.
- `orchestrator/cmd/apibas-runner/main.go`: new `-job-request <file>` mode. It reads one request, runs the scenarios, and writes one `JobResult` to stdout. Exit status 0 only for a completed result. Every failure path writes `status: failed` with a short reason and no reports. The `persistRun` function, the `APIBAS_DB_DSN` environment variable, the `-build` flag and the database import are removed. The CLI no longer writes to PostgreSQL.

### Acceptance requirements (section 5) status after this step
1. No runner database access: DONE. The runner has no database import and reads no DSN.
2. Job idempotency: NOT STARTED. Belongs to step 3 (job key and dispatch).
3. Approval binding: NOT STARTED. Step 4.
4. Result validation: PARTIAL. Schema, job ID, target, scenario set, report count, scenario ID and run tag are checked. Evidence-reference validation is NOT done: the runner's report carries no evidence references yet. Stated gap; must be added before step 3 persists anything.
5. Auditability: NOT STARTED. Steps 3 and 4.
6. Isolation: PARTIAL. Credentials arrive by file, not argument, and the file is read by the owner only. The environment allow-list for the child process is enforced by the orchestrator, so it belongs to step 3.
7. Failure semantics: DONE at the contract level. A crash, malformed output or partial run cannot be validated as completed.
8. Production rejection: NOT STARTED. Step 3 and 4 (execution service).

### Tests and results
- `go test ./internal/apibas/runnerproto/`: 6 tests pass. Valid and invalid requests; unknown fields refused; result false-success cases refused (job mismatch, target mismatch, wrong scenario, missing reports, missing run tag, failed with reports, failed with no reason, completed with an error, unknown status); truncated and unknown-field result refused; credentials file format and permission checks.
- Smoke test of the runner job mode against an unreachable target (`http://127.0.0.1:1`): the run executed and wrote a completed document whose verdict is `ERROR` / `TARGET_UNREACHABLE`; exit status 0. A missing credentials file produced `status: failed` with exit status 1 and no reports.
- Interpretation recorded: job status `completed` means execution finished and every verdict is recorded. It does not mean the target passed. The grade is in each report's outcome.
- Windows cross-compile: `cmd/apibas-runner`, `cmd/apibas-lab`, `cmd/server`: pass.
- Full lab-backed end-to-end run of job mode: NOT run here (needs a running lab with tokens). To run in step 5 on staging.

### Not done (stated)
- Steps 3 to 6 of the approved order.
- No UI work has started. The approved order holds the UI until execution and persistence work end to end.

## API BAS assessment step 3: orchestrator job creation, dispatch, lifecycle, persistence (9 November 2026)

### Deviation from the approved design (stated)
- The design (section 2.4) said results would reuse `apibas_runs`. That table only accepts `build` = vulnerable or fixed, which are lab concepts with no meaning for a target assessment. Step 3 uses two new tables instead: `apibas_jobs` (lifecycle, requester, target, environment, scenario set, credential references) and `apibas_job_reports` (one row per scenario). The lab table is unchanged. This needs approval before step 4 relies on it.

### What changed
- `internal/db/apibas_jobs_schema.go` (new): tables. `environment` is constrained to `lab` or `staging` at the storage layer too, so production is refused in the database as well as in the service.
- `internal/db/apibas_jobs_store.go` (new): `CreateAPIBASJob` (idempotent on `job_key`), `StartAPIBASJob` (queued to running only), `FinishAPIBASJob` (terminal states; a completed job stores its reports in the same transaction; failed and cancelled jobs store none), `ReconcileStaleAPIBASJobs`, and read helpers. Only credential references are stored, never values.
- `internal/apibas/jobs/service.go` (new): `Submit`, `Dispatch`, `ReconcileStale`. Dispatch resolves credentials from the secret store, writes them to a private per-job directory (mode 0600), starts the runner with `-job-request`, and removes the directory on every path. The child's environment is an explicit allow-list (empty on Linux; SYSTEMROOT, TEMP and TMP on Windows). Stdout is capped at 32 MiB and stderr is discarded. The result is persisted only after `runnerproto.ValidateResult` passes. Timeout, cancellation, overflow, malformed output, exit errors and runner-reported failure each end in a failed or cancelled job with no reports.
- `internal/apibas/jobs/testdata/fakerunner/main.go` (new): a test stand-in for the runner, driven by the fixture field, so every failure mode is exercised deterministically.
- `cmd/server/main.go`, `internal/testutil/testdb.go`: create the job tables at startup and in the test bootstrap.

### Defects found and fixed during this step
1. A cancelled job could stay `running`: the outcome write used the cancelled context. Database writes now use `context.WithoutCancel`.
2. The Windows runner child failed to start: the test built the stand-in without `.exe`. Fixed in the test. `New` now also refuses a missing runner binary at startup, instead of failing at the first job.

### Acceptance requirements (section 5) status after step 3
1. No runner database access: done (step 2).
2. Job idempotency: done. The same key returns the same job; a repeated dispatch starts nothing. Tested.
3. Approval binding: not started (step 4).
4. Result validation: done for schema, job ID, target, scenario set and run tags. Evidence-reference validation is still NOT done, because the runner emits no evidence references. Stated gap.
5. Auditability: partly. Requester, target, environment, scenario set, timestamps, outcome and failure reason are stored on the job. Writes to `audit_logs` and the approver field are step 4.
6. Isolation: done for the environment allow-list, the credential file mode, and removal after the run. Tested with a parent variable that must not reach the child.
7. Failure semantics: done and tested for every failure mode.
8. Production rejection: done in the service and in the database. Tested.

### Tests and results
- `go test ./internal/apibas/jobs/`: 11 pass against the Postgres test container. Covered: idempotent submit; production and plaintext credential refusal; completed dispatch persists reports once, and a retry does not re-run; failure modes (malformed, mismatched job, runner-reported failure, non-zero exit after a complete-looking document) store no reports; timeout; cancellation; parent environment not inherited; credential reaches the child, is removed afterwards, and the job holds only the reference; unresolvable credential fails before running; stale running jobs reconciled; store refuses inconsistent terminal states.
- `go test ./internal/db/` for the APIBAS, secret store and app-role tests: pass.
- `go test ./internal/apibas/runnerproto/`: pass.
- Windows cross-compile of server, runner and lab: pass.

### Not done (stated)
- No HTTP endpoint creates or dispatches a job. Step 4 adds authorization first.
- `ReconcileStale` exists but has no periodic caller yet. It must run at startup and on a timer before any job is dispatched in production.
- Dispatch runs only when a caller invokes it. There is no worker queue yet.
- Evidence references are not validated (see requirement 4).
- Not run against a live lab or staging target.

## API BAS assessment step 4: authorization, target scope, approval binding, audit, endpoints (9 November 2026)

### Assumption recorded
- The user said "start step 4" after the step 3 summary flagged that results use new `apibas_jobs` tables instead of `apibas_runs`. This step proceeds on that deviation. It is not an explicit approval of the deviation, so it remains open for the user to reverse.

### What changed
- Permissions (`internal/auth/permissions.go`): `CanRunAPIBAS` (Admin, Analyst), `CanManageAPIBASTargets` (Admin only), `CanApproveAPIBASProduction` (Admin only). Viewers get none.
- Target registry (`apibas_targets`, `internal/db/apibas_targets_store.go`): a target carries the base URL, environment, allowed hosts, allowed scenarios and credential references. A job request names only a target and scenarios. The URL, environment, hosts and credentials always come from the registered target, so a request cannot point the runner at an unregistered host.
- `SubmitForTarget` (`internal/apibas/jobs/target.go`) enforces, in order: target exists; enabled; environment is lab or staging (production is refused in the service); the base URL host is in the target's allowed hosts; every scenario is in the target's allowed scenarios; and no other job is queued or running on the target (per-target advisory lock in one transaction, `CreateAPIBASJobExclusive`). A repeated key returns the existing job, including while the target is busy.
- Approval binding: `Binding` hashes target, environment, fixture, sorted scenarios and sorted hosts. `CheckApproval` rejects an unapproved, self-approved, other-requester, other-target or changed-configuration approval. The store refuses self-approval and a second approval (`apibas_approvals`). Production execution is NOT enabled in this release, so these rules are tested but not reachable in a run.
- Cancellation: `Service.Cancel` stops a job this process is running. The job ends `cancelled` with no reports.
- Endpoints (all under the existing `/api/apibas` licence gate): `POST /api/apibas/targets` (manage targets), `POST /api/apibas/jobs` (run), `GET /api/apibas/jobs/{id}` (view), `POST /api/apibas/jobs/{id}/cancel` (run). Submit returns 202 and starts the job in the background; a repeated key returns 200 with `created:false`.
- Audit (`audit_logs`, written synchronously): `apibas.target.create`, `apibas.job.submit` (before dispatch; if it cannot be written, the job is failed and never started), `apibas.job.finish` (status, reason, timestamps), `apibas.job.cancel`, and `apibas.job.refused` (denied, with the reason). Each carries the actor.
- Server startup (`cmd/server/main.go`): job execution is enabled only when `BAS_APIBAS_RUNNER` names the runner and the encryption key is usable; otherwise the endpoints answer 503 and the log says so. Jobs left running by an earlier process are failed at startup and every 5 minutes (jobs running over 30 minutes), which closes the step 3 gap that `ReconcileStale` had no caller.
- Request bodies reject unknown fields and are capped at 1 MiB. Credentials in a target must be secret-store references; a plaintext value is refused and never echoed.

### Acceptance requirements (section 5) after step 4
1. No runner database access: done (step 2).
2. Job idempotency: done (step 3), plus one active job per target.
3. Approval binding: rules and store done and tested; not exercised by a run because production is disabled. Approval request and approve endpoints are NOT built; they come with production support.
4. Result validation: unchanged. Evidence-reference validation is still NOT done (runner emits none).
5. Auditability: requester, target, scope, timestamps, outcome and failure reason are recorded. The approver field applies to production only and is not recorded yet.
6. Isolation: done (step 3).
7. Failure semantics: done (step 3). Cancellation added.
8. Production rejection: service, database constraint, and endpoint (403 plus a `refused` audit record) all tested.

### Tests and results
- `internal/apibas/jobs` (18 tests, Postgres container): scope (lab, staging, production, disabled, unknown, out-of-scope scenario, host outside allowed hosts), one active job per target, repeat key while busy, cancel of a running job, binding sensitivity to every field, approval rules, store refusal of self-approval and double approval, plus the 11 step 3 tests. Pass.
- `internal/api`: new handler tests pass: role boundaries (no identity, viewer, analyst, admin), target registration refusals (plaintext credential, host not allowed, unknown or empty scenarios, bad environment, bad id, non-http URL, unknown body field), duplicate 409 with a single audit row, the submit flow (202, audit actor, idempotent repeat, 409 busy, 403 production with a refused audit row, 403 out of scope, 404 unknown target, job view without credential names), and 503 without a service. `TestRBACMatrix_*` pass with the four new routes listed.
- `internal/auth`, `internal/license`, all `internal/apibas/...` packages pass (the runner package takes about 500 s). Windows cross-compile of server and runner passes.
- The full `internal/api` suite was not re-run in this step. The earlier full run had one known timing flake (`TestStopIsIdempotent`, Aleef).

### Not done (stated)
- Scope is enforced per target host and scenario. The runner does not yet check each request path against a registered path list; path-level scope is not implemented.
- Approval request and approve endpoints, and production execution.
- Evidence-reference validation.
- No live lab or staging run. Step 5 covers staging end-to-end.
- The job endpoint dispatches in a background goroutine inside the server process; there is no external queue, so a server restart fails running jobs (by reconciliation) rather than resuming them.

## API BAS assessment step 5: end-to-end verification (9 November 2026)

### Status
- LOCAL end-to-end: done and passing. STAGING end-to-end: NOT RUN. Staging (192.168.10.78) was offered, but SSH key authentication from the build host was refused (`Permission denied (publickey,password)`). Passwords were not tried. The staging procedure is in `docs/api-bas-staging-e2e-runbook.md` for someone with access. Step 6 (UI) must not start until that runbook passes.

### Local end-to-end result
- `TestEndToEndRealRunnerAgainstRealLab` builds the real `apibas-runner` and `apibas-lab`, starts a vulnerable and a fixed lab on loopback, registers a target for each, and runs a job through `SubmitForTarget`, `Dispatch`, the secret store and Postgres, with the runner as a child process with an empty environment. Vulnerable build: `completed`, FAIL, exploited, control failed, detection detected. Fixed build: `completed`, PASS, not exploited, control enforced, detection detected. Pass.

### Defects found by this step (all fixed)
1. **Non-loopback targets could never run.** The runner accepts loopback or hosts passed in its allow-list, and the service never passed the target's allowed hosts. Any staging target would have been refused at run time. Jobs now store the target's allowed hosts and the service passes their bare hostnames (`apibas_jobs.allowed_hosts`, `hostnames()`; unit-tested including IPv6). The local test cannot prove this on a real LAN host, so staging must.
2. **The runner was not in the orchestrator image.** `BAS_APIBAS_RUNNER` could not point anywhere in a deployed container. `orchestrator/Dockerfile` now builds `/apibas-runner` (plain `go build`, not garble, because the runner's report types have no json tags and garble breaks reflection-based output). `docker-compose.yml` passes `BAS_APIBAS_RUNNER` through from `.env`, empty by default, so existing installs are unchanged. The Dockerfile change was NOT built into an image here; only the Linux runner build and `docker compose config` were checked.
3. **First upgrade of an existing install would abort.** `install.sh --upgrade` refused when the encryption key was missing, but an install from before this work has never had one. A marker `<DATA_DIR>/.db-key-issued` now records that a key was issued. No marker and no key: the upgrade generates one (nothing can be encrypted under a key that never existed). Marker present and key missing: the upgrade still refuses. Shell tests: 13 pass as root and as UID 1000 in Linux, including both cases.
4. **No way to store a target credential.** Targets accept only secret-store references and nothing could write one. `POST /api/apibas/targets` now accepts a write-only `credentials` map: values are encrypted into the secret store, the target keeps references only, and the values are never returned, audited or stored in the target row (audit lists names only). A name given both as a reference and a value is refused before anything is stored. Tested.

### Tests and results
- `internal/apibas/jobs` (all, including end-to-end and the hostname test): pass.
- `internal/api`: target and job handler tests, the write-only credential test, RBAC matrix tests: pass.
- `packaging/compose/tests/db_encryption_key_test.sh`: 13 of 13, root and UID 1000. `setup-install-state.test.sh`: pass.
- `GOOS=linux` runner build and `docker compose config`: pass.

### Not done (stated)
- Staging run (section above). Also not verified on staging: the compose mount of `/etc/audspect/secrets`, the image build, the container's temp directory for per-job files, and runner access to a LAN host.
- No credential rotation or update path for an existing target (registration only).
- Evidence references still not validated; path-level scope not implemented.

## API BAS assessment: evidence reference validation and path-level scope (9 November 2026)

### What changed
- **Path scope (new package `internal/apibas/scope`).** A target now carries `allowed_paths`: path prefixes compared by whole segment (`/api/orders` covers `/api/orders/ORD-1`, not `/api/orders-admin`). Matching is case-sensitive and refuses anything it cannot reason about: not rooted, backslash or NUL, empty or `.`/`..` segments, or percent-encoded forms that decode to those or to a slash.
- **Registration.** `allowed_paths` is validated (no bare `/`, no query or fragment, no dot segments) and is required for staging and production targets. A lab target may omit it, which means unrestricted (loopback lab only). Paths are copied onto each job, like allowed hosts.
- **Runner enforcement, two layers.** (1) Before a scenario runs, `runner.CheckScope` checks the fixed part of every step path (before any placeholder); a scenario that could leave scope fails the job before anything is sent, with a reason naming the step. (2) `Runner.do` refuses to send any path outside scope even if (1) was bypassed. Because paths must be rooted, absolute URLs and `@host` authority tricks are refused as a side effect.
- **Orchestrator enforcement.** `ValidateResult` re-checks every recorded exchange path against the job's scope, so a misbehaving runner cannot store evidence of an out-of-scope request.
- **Evidence reference validation.** `ValidateResult` now requires each report to have a well-formed run tag (`[A-Za-z0-9_-]{6,64}`) unique within the job, and each exchange to have a step id, a known HTTP method, status 0 or 100 to 599, and a non-negative leak count. A result failing any check is not stored, so every evidence reference the results API later builds (`<run tag>#<index>`) resolves to a valid, in-scope exchange.
- **Approvals.** `Binding` now includes the allowed paths, so changing the path scope invalidates an approval (production is still not executable).

### Tests (all pass)
- `scope`: segment matching, traversal and encoded forms, empty list, prefix validity, static prefix.
- `runnerproto`: evidence field checks, duplicate and malformed run tags, path-scope enforcement on recorded exchanges, no-scope behaviour.
- `runner`: `CheckScope` table (placeholders, siblings, traversal, absolute URL, authority smuggling) and the send-time refusal without network access.
- `jobs` end-to-end with the real runner and lab: unscoped vulnerable FAIL and fixed PASS as before; a target scoped to `/api` completes PASS; a target scoped to `/health` fails the job with "outside the target's allowed paths" and stores no report.
- `api`: registration refusals and acceptance; RBAC matrix tests unchanged and passing. Existing non-lab test targets now carry a default path scope.

### Limits stated plainly
- The exchange record is made by the runner; the orchestrator validates its shape and scope but cannot independently confirm the request was actually sent. Validation catches malformed or out-of-scope evidence, not a runner that fabricates in-scope exchanges. (The runner is a trusted binary shipped in the same image.)
- The runner's lab-admin channel (state reads, reset, events, authenticated with the admin token) is outside this scope check. It is only used against lab-style targets that expose that interface.
- Scenarios that deliberately use traversal or odd path forms (for example path-normalisation tests) cannot run on a target with a path scope; they fail the pre-check by design. Unscoped lab targets still run them.
- Submission does not pre-check scenarios against the target's paths; a mismatch is reported when the job runs (job `failed`, reason names the step, no reports).
- Existing staging or production targets registered before this change have no paths and would be refused only at registration of new ones; none exist outside tests. No migration needed beyond the added columns (`apibas_targets.allowed_paths`, `apibas_jobs.allowed_paths`, created at startup).
- Not run on staging (see the staging runbook).

## API BAS production approval endpoints (9 November 2026)

### What changed
- `POST /api/apibas/approvals` (permission: run API BAS): records a request to approve one exact production configuration (target, fixture, scenario set). The server loads the target, refuses non-production targets (400), unknown targets (404) and scenarios outside the target's allow-list (403), and computes the binding hash itself from the target's registered hosts and paths, so the requester cannot choose what is bound.
- `POST /api/apibas/approvals/{id}/approve` (permission: approve production, Admin only): records the approver. Refused with 403 when the approver is the requester, 409 when already approved, 404 when unknown. Refusals are audited (`apibas.approval.refused`). The SQL update also enforces both rules, so a race cannot approve twice or let the requester approve.
- `GET /api/apibas/approvals/{id}`: status (pending or approved), requester, approver, times, and `executable:false`.
- Audit actions: `apibas.approval.request`, `apibas.approval.approve`, `apibas.approval.refused`. RBAC matrix updated; the matrix tests pass.

### Tests
Full flow in `TestAPIBASApprovalFlow`: staging target refused, unknown target, out-of-scope scenario, analyst can request but not approve (RBAC), admin cannot approve own request, a different admin approves, a third gets 409, unknown id 404, GET shows approved with the approver and `executable:false`, audit rows present.

### Not done (stated)
- Production execution remains refused by the job service (unchanged by decision for the first release). An approved record does not make anything run; `jobs.CheckApproval` is still not called by any execution path.
- Approvals do not expire and cannot be revoked or listed. Before production execution is enabled they need an expiry, single-use consumption and a revoke endpoint.
- Not run on staging.

## API BAS approvals: expiry, revoke, single use (9 November 2026)

### What changed
- **Expiry.** A granted approval expires 24 hours after it is approved (`expires_at`, set by the database at approval time). A request left unapproved for more than 72 hours can no longer be approved. Both windows are constants in `db` (`ApprovalValidity`, `ApprovalRequestWindow`); they are not configurable yet.
- **Revoke.** `POST /api/apibas/approvals/{id}/revoke` (Admin-only approve permission) with an optional reason (max 500 characters). Works on pending and approved approvals; 409 if already revoked or already used; 404 if unknown. A revoked request cannot be approved. Audited as `apibas.approval.revoke` (refusals as `apibas.approval.refused`). Any holder of the approve permission may revoke, including the requester if they are an Admin.
- **Single use.** `db.ConsumeAPIBASApproval` marks an approval used by a job in one conditional update (approved, unexpired, unrevoked, unused), so jobs racing for one approval cannot both get it. A used approval cannot be revoked.
- **Check rules.** `jobs.CheckApproval` now also refuses revoked, used, expired, and approvals with no recorded expiry (including any approval created before this change), and takes the current time as an argument.
- **View.** `GET /api/apibas/approvals/{id}` reports status `pending`, `approved`, `expired`, `revoked` or `used`, plus expiry, revoker and reason, and the using job. Still `executable:false`.
- Schema: six columns added to `apibas_approvals`, created at startup.

### Tests
Store lifecycle test: expiry about 24 hours ahead; first consume wins and a second is refused; 8 concurrent consumers produce exactly one winner; revoked, pending and expired approvals cannot be consumed; a used approval cannot be revoked; a stale or revoked request cannot be approved. Handler test: revoke, double revoke, analyst forbidden, approve-after-revoke, expired and used status, revoke-after-use, audit row. `CheckApproval` table extended. RBAC matrix updated.

### Not done (stated)
- Nothing calls `ConsumeAPIBASApproval` or `CheckApproval` yet: production execution is still refused, so no job consumes an approval. Wiring them into the execution path (check, then consume inside the same step that creates the job) is the work that enables production.
- No list endpoint for pending approvals, and no notification to approvers.
- Not run on staging.
