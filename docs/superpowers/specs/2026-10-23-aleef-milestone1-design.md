# Aleef — Milestone 1 design: business-logic and authorization flaw discovery for BFSI APIs

Status: APPROVED 2026-10-23 (owner decisions in section 10). Nothing is built. Source discussion: `Audspect_Aleef.txt`.

## 1. Intent

Aleef is a vulnerability-discovery capability that sits beside the API BAS engine. API BAS replays a
catalogue of scenarios someone already wrote (120 today). Aleef derives tests from the application it
is pointed at and checks them against stated security properties, so it can find a flaw no catalogue
entry names.

Milestone 1 target: internet-banking and payment-style REST APIs used by Indian and UAE BFSI
institutions, tested in an explicitly authorized UAT environment with synthetic accounts.

Milestone 1 finds **business-logic and authorization flaws**. It does not do fuzzing, memory-safety
research or source-code analysis (those are Milestone 4 and need a researcher hire).

## 2. Goals, non-goals, anti-goals

Goals
- G1. Given an API description and test accounts, generate tests the catalogue does not contain.
- G2. Judge each test against a declared security property with a deterministic oracle.
- G3. Report two classes of result, kept apart: **candidate** and **verified**.
- G4. Convert each verified finding into a regression scenario that re-runs after a fix.
- G5. Run safely against UAT: authorization first, no money movement, rate limits, cleanup.
- G6. Prove it on a benchmark with known ground truth (recall and false-positive rate).

Non-goals
- No fuzzing, no memory-corruption work, no source-code analysis, no binary analysis.
- No zero-day claim. Milestone 1 findings are "new to Audspect". Disclosure status is a separate,
  human-verified field (see 8).
- No production testing. No real customer data. No real payment rails.
- No LLM in Milestone 1. The generator is deterministic.
- No new scenario-execution engine. Aleef drives the existing runner.

Anti-goals (a technically working build that still counts as failure)
- A finding labelled verified that a human cannot reproduce from the evidence.
- A test that moves real money, locks a real account or sends real notifications.
- A false-positive rate high enough that a bank team stops reading the output.

## 3. The three firm rules, and how the design honours them

1. Reuse the API BAS runner, evidence and verification mechanisms where the code supports it. See 4
   for what the code does and does not support.
2. Candidates and verified findings are separate types, separate tables and separate UI states. A
   verified finding can only be produced by the verifier (5.5), never by the generator or the runner.
3. Safe UAT testing: engagement authorization, transaction safety classes, rate limits, kill switch
   and cleanup are enforced in code before any request leaves (5.6).

## 4. Repository mapping

Read from the code on 2026-10-23.

### 4.1 What exists and Aleef reuses as-is

| Existing piece | Where | Reuse in Aleef |
|---|---|---|
| Scenario contract (`contract.Scenario`, `Step`, validation, side-effect classes READ_ONLY / STATE_CHANGE_SANDBOX) | `internal/apibas/contract` | The generator emits `contract.Scenario` values. They pass the same `Validate()`. |
| Runner: baseline + attack steps, repeat, parallel (race), co-actor, auth modes valid/none/revoked, secret resolution, per-run tag, evidence redaction, cleanup | `internal/apibas/runner` | Executes every generated test. No second HTTP engine. |
| Grader: PASS/FAIL/ERROR/SKIPPED with exploitability and control axes, and a reason code | `internal/apibas/grade` | First-pass oracle for each run. Output feeds the verifier. |
| Leak detection by forbidden values at any JSON depth; uninspectable responses never pass | `runner/forbidden.go` | Used with canary values Aleef plants in UAT (5.2). |
| Detection stage and SIEM events | `internal/apibas/detect`, `runner/detection.go` | Phase 2 only: after a finding is verified, check whether the bank's monitoring saw it. |
| Regulatory registry (RBI, UAE PDPL mappings, source-backed) | `internal/apibas/regulatory` | Verified findings carry regulatory mapping the same way scenarios do. |
| Catalogue loader | `internal/apibas/catalog` | Needed for the "not already covered" check (5.4). |
| `targetscope.IsAuthorized(host, scope)` | `internal/targetscope` | Host/CIDR check inside the engagement gate. |
| `injectionapproval` (TTL approval record, Verify-before-act, customer vs lab classification) | `internal/injectionapproval` | Pattern for the engagement approval. Copy the discipline; the record shape differs. |
| Lab with vulnerable and fixed builds and seeded faults | `internal/apibas/lab`, `cmd/apibas-lab` | The benchmark (5.8). |
| Run API, RBAC permission, product/license gate | `internal/api/apibas_handlers.go`, `internal/auth`, `internal/license` | New Aleef routes follow the same pattern and get their own permission. |

### 4.2 What exists but does NOT fit, and what we do about it

| Gap | Evidence in code | Consequence | Plan |
|---|---|---|---|
| The runner assumes the fixture is shared with the target. Identities, objects, and protected values are compiled in (`fixture.OrdersTwoTenant()`). | `internal/apibas/fixture/fixture.go` | A real UAT app has no compiled-in fixture. | Aleef builds a `fixture.Fixture` at run time from the application model and from objects it creates in UAT under its own test accounts (5.2). |
| `Config.Reset` restores a seed state. UAT cannot be reset. | `runner.Resetter`, scenarios with STATE_CHANGE_SANDBOX | State-changing tests would have no safe cleanup. | Implement `Resetter` as **compensating cleanup**: cancel/delete only the objects Aleef created, identified by run tag. If an operation has no compensation, it is not generated (5.6). |
| Ground truth uses `StateReader` against lab admin endpoints (`/lab/...`). | `runner/labadmin.go` | UAT has no lab admin plane. | A UAT `StateReader` that reads state through the application's own read endpoints, as the owning account. Where a property cannot be checked from the API, the test is not generated. |
| Paths use one `{object}` placeholder and one baseline plus one attack step. | `contract.Step`, `runner.run` | Multi-step workflows (initiate, authorize, tamper, settle) don't fit a single attack. | Use `co_actor` setup steps for prefix steps; only the final step is graded. Anything needing richer sequencing is out of Milestone 1 and recorded as a limit. Do not extend the contract unless Phase 2 needs it. |
| `apibas_runs.build` is CHECK IN ('vulnerable','fixed'). | `internal/db/apibas_schema.go` | UAT runs are neither. | Aleef gets its own tables (5.7). Do not loosen the existing constraint. |
| `cmd/apibas-runner` refuses non-loopback hosts unless `-allow`. | `cmd/apibas-runner/main.go` | Correct for the lab, too weak for a customer UAT. | Aleef does not reuse `checkTarget`. It uses the engagement gate. |
| `internal/evidence` is an asset/threat-observation store (trust, completeness, sync). | `internal/evidence/types.go` | Not a fit for request/response proof. | Not reused. Finding evidence lives in the Aleef tables as sanitized exchanges, using the runner's own redacted `Exchange` records. |
| `internal/verification` is the analyst-attestation store for detection coverage. | `internal/verification/store.go` | Different domain. | Reuse only its idea: append-only history, no in-place status overwrite. Not the code. |
| `variant` and `rulelib` | `internal/variant`, `internal/rulelib` | Variant is PowerShell obfuscation; rulelib is Sigma detection rules. Neither generates API tests. | Not reused. The existing "rule" concept for Aleef is new: security properties (5.3). |

### 4.3 What must be built from scratch

Application model and spec importer; security-property library; test generator; deduplication against
the catalogue; verifier; engagement gate and transaction-safety classifier; UAT state reader and
compensating cleanup; candidate and finding stores; regression-scenario export; benchmark harness;
console tab.

## 5. Design

New package tree `internal/aleef/`, one responsibility per package:

```
aleef/model      application model + OpenAPI/Postman import
aleef/property   security-property definitions and oracles
aleef/generate   test generation, deterministic
aleef/novelty    "is this already in the catalogue" check
aleef/safety     engagement, transaction classes, rate limit, kill switch
aleef/uat        UAT StateReader + compensating Resetter
aleef/verify     the only producer of verified findings
aleef/store      candidates, findings, history (Postgres)
aleef/export     verified finding -> regression scenario
aleef/bench      benchmark harness
```

### 5.1 Application model (`model`)

Input: an OpenAPI 3 document or Postman collection, plus an engagement file listing test accounts
(by secret reference, never inline token) with their role and customer. The importer produces:
- Operations: method, path template, request schema, which path/query/body fields are object
  identifiers, response schema.
- Roles and which test account holds which role.
- Resource ownership: which account owns which object, learned by creating objects under each account
  through operations the operator marks as "setup safe" (5.6).
- Workflow state machines for payment-like resources: declared by the operator as a short YAML
  (states, which operation moves between them), because inferring it from a spec is unreliable.
  Milestone 1 does not try to infer state machines.

Anything the importer cannot classify is reported as "not modelled", not guessed.

### 5.2 Fixture and canaries

For each test account Aleef creates one or more objects through setup-safe operations, with
distinctive canary values in free-text fields (for example `ALEEF-CANARY-<run>-<account>`). These feed
`fixture.Object.Protected`, so the existing `forbidden.go` leak search works unchanged: if account B's
response contains account A's canary, that is a deterministic cross-account leak.

If an application offers no free-text field to carry a canary, leak tests for that resource use
structural comparison (the object id and owner field in the response) and are marked lower-confidence.

### 5.3 Security properties (`property`)

A property is data: an id, the preconditions it needs from the model, the test template, and the oracle.
Milestone 1 properties:

| Id | Property | Oracle |
|---|---|---|
| P-OWN-1 | Account B cannot read account A's object | Canary or owner-id of A in B's response, or 2xx where the control should deny |
| P-OWN-2 | Account B cannot modify or delete A's object | State reader shows A's object changed |
| P-OWN-3 | Object ids in every ID-bearing field are checked, not only the path (body, query, header, nested) | Same as P-OWN-1/2, per field |
| P-ROLE-1 | A lower role cannot call an operation reserved for a higher role | 2xx or state change |
| P-ROLE-2 | Versioned or alternative routes enforce the same checks as the primary route | Differential result across versions/channels |
| P-AUTH-1 | A payment cannot be executed without its required authorization step | Final state reached without the step |
| P-AUTH-2 | Changing amount or beneficiary after authorization invalidates the authorization | Final state shows altered values on an authorized payment |
| P-MC-1 | Maker cannot approve own item; the same account cannot be both maker and checker | State shows self-approval |
| P-IDEM-1 | A repeated request with the same idempotency key does not process twice | Count of resulting records > 1 |
| P-IDEM-2 | Same key with a different body is refused | Second body accepted |
| P-STATE-1 | A resource cannot move through an invalid transition | State reader shows the invalid state |
| P-STATE-2 | A failed or reversed payment is never reported as successful | Status response contradicts final state |
| P-RACE-1 | Concurrent requests cannot exceed a limit (balance, once-only action) | Aggregate exceeds the limit |

Several of these overlap existing catalogue scenarios (BOLA, BFLA, idempotency, maker-checker,
race). That is intended: the catalogue tests them on one hard-coded endpoint; Aleef applies the same
property to every applicable operation in an application it has never seen. What is new is
coverage across operations, fields, roles and sequences, not new vulnerability classes.

### 5.4 Generation (`generate`) and novelty (`novelty`)

For each property, enumerate every applicable (operation, identity pair, field) combination from the
model, then vary: identifier source (another account's id, a guessed neighbour, a stale id), field
location, HTTP method override, API version, request order, boundary values (zero, negative, maximum,
rounding), repeat count and parallelism. Output: `contract.Scenario` values.

Rules:
- Deterministic: same model and same seed produce the same tests.
- Bounded: a per-engagement cap on the number of tests, so a large API cannot create an unbounded run.
- Every generated test is tagged with the property it targets and the parameters that produced it.

Novelty check: a generated test is "already covered" if a catalogue scenario has the same property
class and same (method, path shape) after normalization. Tests that are covered are still run, but
they are labelled so a finding from them is **not** counted as new-to-Audspect. The headline metric
only counts findings from non-covered tests.

### 5.5 Verification (`verify`) — candidate versus verified

States: `generated` → `executed` → `candidate` | `clean` | `inconclusive` → `verified` | `rejected` | `unconfirmed`.

- `candidate`: the runner graded the test FAIL/exploited on one run. Nothing more is claimed.
- `verified` requires all of:
  1. Reproduced on N consecutive independent runs (default 3), each starting from freshly created objects.
  2. A positive control passed: the same operation by the legitimate owner behaves as expected, so the
     failure is not a broken test or a broken environment.
  3. A negative control passed: the same test with a control that must fail (for example, the attacker
     identity against an object the attacker is explicitly allowed to access) does not produce the
     finding, so the oracle is not firing on everything.
  4. Evidence complete: sanitized request/response pairs, the state diff, the property id, and the
     reproduction steps, hashed.
  5. Deterministic oracle only. No model output participates in this decision.
- `rejected`: failed a control or did not reproduce; kept in history with the reason.
- `unconfirmed`: reproduced but the oracle cannot distinguish a flaw from intended behaviour (for
  example a role that may legitimately have this access). Needs a human decision.

Only the verifier writes `verified`. The generator and runner cannot. A verified finding also records
`prior_knowledge`: `not_checked` by default, set only by a human after checking public and vendor
sources. Reports say "new to Audspect" and never "zero-day" unless a human sets that field.

### 5.6 Safety (`safety`, `uat`)

Enforced in code, before any request leaves. Failure of any check is a refusal, not a warning.

1. **Engagement record.** No run without one: customer, approved base URLs/hosts (checked with
   `targetscope.IsAuthorized` plus exact-origin match), environment class (`uat` only in Milestone 1;
   `production` is rejected), named approver, validity window (TTL pattern from `injectionapproval`),
   permitted accounts, permitted operations, request budget, and a contact for stop requests.
2. **Transaction safety classes.** Every operation in the model gets a class:
   - `READ` — GET and equivalent.
   - `SETUP_SAFE` — creates a synthetic object with a known compensation (cancel/delete).
   - `STATE_CHANGE_REVERSIBLE` — can be undone by a declared compensating operation.
   - `MONEY_MOVEMENT` — payment initiation, transfer, disbursement, reversal.
   - `NOTIFYING` — sends SMS, e-mail, push, or webhook to a person or external system.
   - `UNKNOWN`.

   Default policy: READ, SETUP_SAFE and STATE_CHANGE_REVERSIBLE are allowed. `MONEY_MOVEMENT` runs
   only if the engagement states the UAT payment rail is simulated, and only against a declared
   simulator beneficiary list. `NOTIFYING` runs only against operator-listed test recipients.
   `UNKNOWN` never runs. Classification is by the operator; the importer suggests, never decides.
3. **Rate limit and budget.** Requests per second, concurrent requests, and total requests per run, set
   in the engagement. Race tests (`parallel`) count against the concurrency cap. A 429, repeated 5xx
   or latency growth beyond a threshold halts the run (circuit breaker).
4. **Kill switch.** Cancel is checked between every request. The existing run-cancel mechanism is
   reused where possible; otherwise a context cancellation tied to the engagement.
5. **Compensating cleanup.** `uat.Resetter` removes only objects tagged with the run tag. If cleanup
   fails, the run ends ERROR (`CLEANUP_FAILED` already exists) and lists orphaned objects for the
   customer. A test class with no compensation is not generated.
6. **Account lockout awareness.** Authentication-failure tests are limited per account with a ceiling
   below the application's stated lockout threshold, if given; otherwise they are not generated.
7. **Data.** Only synthetic accounts and objects created by Aleef. Evidence is redacted by the
   runner's existing rules. Aleef stores no customer secrets; tokens are referenced by secret ref.

### 5.7 Storage (`store`)

New tables, not the existing `apibas_runs`:
`aleef_engagements`, `aleef_runs`, `aleef_tests` (generated test + params + property), `aleef_results`
(per-execution graded outcome with the runner's report as jsonb), `aleef_findings` (state, history
append-only, `prior_knowledge`, evidence hash). Status changes append a history row; no in-place
overwrite. Migration follows the existing versioned-migration convention.

### 5.8 Regression and benchmark

Regression: `export` turns a verified finding into a standard `contract.Scenario` YAML with the
fixture reference and a negative test, in the Aleef namespace (for example `ALEEF-REG-0001`). It
re-runs after a fix; a pass confirms the fix, a fail reopens the finding.

Benchmark (the Milestone 1 acceptance test) uses the existing lab, which already has vulnerable and
fixed builds:
- Seed a set of **held-out** flaws in a new lab domain (a small bank-like API: accounts, beneficiaries,
  payments with authorize/settle, maker-checker). Held-out means: the flaws are written and recorded
  before the generator exists and are not in the catalogue.
- Aleef is given only the OpenAPI description and test accounts, not the catalogue or lab source.
- Metrics: recall on held-out flaws, false positives on the fixed build (target zero verified findings
  there), reproducibility, time to verify, and whether the fixed build turns each finding clean.
- Milestone 1 passes when it verifies at least the agreed number of held-out flaws, shows zero
  verified findings on the fixed build, and at least one verified finding comes from a non-covered test.

Caveat to state in the QA log: if the same person writes the held-out flaws and the generator, the
benchmark proves less. Prefer that the held-out flaw list is written by someone other than the
generator's author (Zain, or written in an earlier commit).

## 6. Phasing inside Milestone 1

- **M1.1** Model + importer + engagement/safety gate + UAT state reader/cleanup, tested on the lab.
- **M1.2** Property library + generator + novelty check. Ownership, role, idempotency first.
- **M1.3** Verifier, stores, API routes, console tab.
- **M1.4** Payment-state and maker-checker properties, regression export, benchmark run and QA log.

Each sub-milestone ends with an entry in `docs/aleef-mastery-qa-log.md`, per the saved-QA convention.

## 7. Constraints

- On-prem; no data leaves the install. No external AI service in Milestone 1.
- Go in `internal/aleef`; Windows cross-compile and fresh-clone build must pass.
- Scenario signing: generated scenarios are not catalogue entries and are not signed; exported
  regression scenarios that enter the catalogue must follow the existing re-sign rule.
- New RBAC permission and product/license gate, following `CanViewAPIBASRuns` and `product_gate.go`.

## 8. Decisions for the builder (my calls, marked) and open items

My calls (change any of these):
- Own tables rather than extending `apibas_runs`.
- Verification threshold of 3 reproductions and both controls.
- Operator declares state machines; the importer does not infer them.
- Tests that overlap the catalogue still run but do not count toward the "new" metric.
- Production environment is refused in Milestone 1.
- Wording: "new to Audspect", never "zero-day", until a human sets `prior_knowledge`.

Open items that need the owner:
1. Who writes the held-out benchmark flaws, so the benchmark is not self-graded?
2. Real BFSI UAT access: until a design partner provides a UAT environment, only the lab proves this.
   Is there a candidate institution or vendor sandbox (a bank sandbox, an open-banking test API)?
3. Required minimum for "Milestone 1 passed": number of held-out flaws verified.
4. Pricing/licensing tier for Aleef (affects the product gate).
5. Whether verified findings should feed the existing exposure/attack-path views in Phase 2.

## 9. Not covered, stated plainly

Aleef Milestone 1 will not find: injection or parsing bugs needing payload research, memory-safety
bugs, flaws that need source access, cryptographic weaknesses, or anything that cannot be observed
through the API and its state reads. It will miss flaws in workflows the operator did not model. A clean
Aleef run is not evidence that an application is secure.

## 10. Owner decisions (2026-10-23) — these override anything above that conflicts

1. **Approved:** Milestone 1 as designed. Production testing is prohibited in this milestone.
2. **Benchmark authorship.** The owner defines the benchmark specification and the hidden flaw cases.
   The generator's implementers do not receive the hidden cases or their exact trigger conditions until
   evaluation. The target is a synthetic bank API, never a real banking system.
3. **Eight held-out flaws** (property level only is visible to implementers):

   | ID | Flaw | Property |
   |---|---|---|
   | H1 | Cross-customer object access | Customer B cannot read A's account or transaction |
   | H2 | Unauthorized object modification | A customer cannot modify another's beneficiary or payment |
   | H3 | Approved payment tampering | Changing amount/beneficiary after approval invalidates the approval |
   | H4 | Idempotency failure | Same idempotency key cannot create a second transaction |
   | H5 | Invalid payment-state transition | Payment cannot reach settled without required authorization steps |
   | H6 | Maker-checker bypass | Initiator cannot approve their own transaction when dual control is required |
   | H7 | Cross-tenant document exposure | Customer cannot reach another's KYC document via an alternate endpoint |
   | H8 | Inconsistent authorization across API versions | Older version enforces the same access rules as the current one |

   Each has an independently seeded defect and a fixed counterpart. The cases stay out of the generator's
   catalogue and hard-coded rules (recognition test vs discovery test).
4. **Pass criteria for Milestone 1:** at least 6 of 8 held-out flaws verified (75%); 0 verified false
   positives on fixed controls; 3 consecutive reproductions from fresh objects; legitimate-owner control
   and negative control pass for every verified finding; every verified finding has reproducible evidence
   and a saved regression test; all safety controls pass with no unauthorized money movement or
   production execution; all 8 flaws have documented ground truth and a fixed build.
   Reporting: individual per-flaw results and exact test coverage, never recall alone. 6/8 is a
   prototype acceptance threshold, not proof of broad discovery capability.
5. **Implementation order:** (1) freeze benchmark spec and hidden cases; (2) build vulnerable and fixed
   synthetic bank API; (3) application model and deterministic generator; (4) connect to the API BAS
   runner; (5) candidate storage, verification, Aleef run records; (6) UAT engagement controls, reversible
   cleanup, rate limits, emergency stop; (7) held-out evaluation, results published internally.
   This reorders section 6: the benchmark comes first, and safety/storage come after the generator works
   on the lab.
6. **Licence:** Aleef is a separate product, outside the existing three tiers. It needs its own gate in
   `internal/license` and `product_gate.go`; the tier mapping is part of the plan.
7. **UAT access:** none available. The lab is the only proof in Milestone 1. Claims must say so; no
   statement about real-bank readiness until a design-partner UAT run exists.

## 11. Implementation constraints that follow from the decisions (builder's notes)

- **Sealed defects.** The seeded-defect code (trigger conditions for H1-H8) must be written by someone
  who is not the generator's implementer, and kept where the implementer does not read it (separate
  package path, built into the lab binary behind a defect-flag interface). The implementer builds the
  clean API skeleton, the fixed build, the OpenAPI document and the defect-flag hook, and nothing else.
  Note: the implementing assistant has seen the property list above (it is in the visible spec) but not
  the trigger conditions; the QA log must state this exactly.
- **No catalogue leakage.** The generator and its tests must not import the benchmark package, the
  sealed defects, or read hidden labels. A build-time check (import-graph test) enforces this.
- **Evaluation harness reads labels only after the run.** Labels live outside the generator's inputs.
- **Generator properties stay general** (section 5.3). They must not be tuned to the eight cases; any
  property added after seeing benchmark results must be recorded as post-hoc in the QA log.
