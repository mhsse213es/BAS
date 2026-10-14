# TCF Phase 6 — Automated Validation Lab Design

**Goal:** Give TCF-originated content a real, evidence-backed EXECUTION-level validation step — dispatched to a factory-owned lab agent that a customer target can never be substituted for, re-checked for safety immediately before it runs, and recorded honestly (pass, fail, or inconclusive — never a fabricated pass) — and make that validation a precondition for publishing TCF-originated content, without touching the operator hand-authored publish path at all. TELEMETRY/DETECTION-level validation and ephemeral container/VM provisioning are explicitly deferred past v1.

## 1. Current-state evidence (gap analysis, verified against code)

### 1.1 `dispatchRun` has no ownership/ACL check of any kind
`(h *Handler) dispatchRun(ctx, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID, skipReason string, err error)` (`handlers.go:1838`) validates only agent state, OS compatibility, and concurrency limits — any registered agent, including a customer's, can be dispatched to today. The `agents` table (`internal/db/postgres.go:64-76`) has no ownership/scope column; `env_label` (line 71) is free-text display-only, not an access gate. The table already carries an established idempotent-migration pattern (`ALTER TABLE agents ADD COLUMN IF NOT EXISTS ...`, lines 79-84) for exactly this kind of addition.

### 1.2 `dispatchOpts.Mode` has three values today, none of them factory-owned
Modes are `"posture"|"telemetry"|"lab"` (`handlers.go:1645`, `:2348`). `"lab"` mode is customer-facing: it carries a `ConfirmLab` double-confirmation gate (`handlers.go:2364`) and targets the *customer's own* isolated range. Reusing the string `"lab"` for factory-internal validation would be wrong — its existing meaning assumes a customer target and a confirmation step that doesn't apply here.

### 1.3 Zero dispatch-time safety gate exists for any target
`safetyVerdict`/`combinatorialRisk` (Phase 4/5) only run once, at `Compose`/`RegisterGenerated` time — never re-checked at dispatch. Content that passed safety at creation is never re-verified before it actually executes.

### 1.4 `content_validations` already has the enforcement mechanism this phase needs
`CHECK (level IN ('STRUCTURAL','STATIC') OR outcome <> 'PASS' OR run_id IS NOT NULL)` (`content_registry_schema.go:145`) — the DB itself already refuses a fabricated EXECUTION/TELEMETRY/DETECTION `PASS` with no real `run_id`. Critically, this constraint only fires on `outcome='PASS'` — an `ERROR`/`FAIL`/`NO_DATA` outcome with `run_id=NULL` is already legal, which is exactly what an honest dispatch-failure record needs. `outcome` already has `ERROR`/`NO_DATA`/`NOT_APPLICABLE` as first-class values distinct from `FAIL` (no new taxonomy needed). The only production write today is STRUCTURAL level (`store.go:292-297`); `'STATIC'` is never written by any production code; EXECUTION is cheap to populate from `scenario_runs.status/results/score` (already structured); TELEMETRY/DETECTION require `internal/detectverify`, which is hard-wired to customer SIEM credentials and not reusable for a factory-internal target as-is — this is the concrete reason v1 scopes to EXECUTION only.

### 1.5 `VALIDATING`'s lifecycle transitions already support a system actor, fully tested, today
`Registry.Transition(ctx, versionID, to, actor, reason string) error` (`intake.go:285`) is a plain Go method with no HTTP/JWT dependency — callable directly from internal code. `CheckTransition` (`lifecycle.go:40`) and its rule table (`lifecycle.go:20-35`) already mark `DRAFT→VALIDATING` as unrestricted and both `VALIDATING→VALIDATED` and `VALIDATING→DRAFT` as system-actor transitions (`IsHumanActor(actor)` must be false) — already exercised by a real test (`lifecycle_test.go:58`, using `ActorGenerator` for `VALIDATING→DRAFT`). No lifecycle-table changes are needed for this part. Phase 11's analytics already reads `VALIDATING` as a "stuck validation" signal (`analytics/factory.go:201,232-235`), so this phase's own timeout handling (never leaving content in `VALIDATING` indefinitely) directly feeds an existing consumer.

### 1.6 `DRAFT→PUBLISHED_LOCAL` bypasses validation entirely today — for both TCF and operator content
`transitionRules` allows `DRAFT→PUBLISHED_LOCAL` directly, human-actor-gated, no required prior state (`lifecycle.go:27`). Separately, `RegisterLocalApproved` (`intake.go:215-253`) creates a content version **already in `PUBLISHED_LOCAL`**, bypassing `DRAFT` and the generic `Transition` path entirely — this is the operator "save" flow behind the admin UI's hand-authored custom scenarios. Per explicit direction, this operator path is **out of scope** for this phase and stays byte-for-byte unmodified; only TCF-originated content's route to `DRAFT→PUBLISHED_LOCAL` gets the new gate.

### 1.7 TCF-origin is cleanly distinguishable at the row level — but not via the columns that look like they should carry it
`origin` (`Origin{VENDOR,LOCAL}`) and `source` (`IntakeSource{builtin,custom,intel}`) are both ambiguous: `Compose` and `RegisterLocalApproved` can both produce `origin=LOCAL, source=custom`. The real, unambiguous marker is `created_by` (the DB column populated from `newVersion.actor`): `types.go:58-60` defines `ActorIntake = "intake"` (human/operator, used by `RegisterLocalApproved`, `intake.go:166`), `ActorGenerator = "generator:connector"` (pure TCF generation, `generated.go:53`), and `ActorComposer = "composer:admin"` (TCF Phase 4 composition, `compose.go:91`). TCF-originated content is therefore exactly `created_by IN ('generator:connector', 'composer:admin')`.

### 1.8 A DRAFT version can be turned into a runnable `*scenario.Scenario` without going through the publish gate
`Registry.ResolveExecutable` (`gate.go:26`) is deliberately gate-enforced — it only resolves a version that already passes `Executable(v.Origin, v.Trust, v.Lifecycle, ...)` (`gate.go:42`), which a `DRAFT` version never does. It is the wrong primitive for this phase: dispatching a `DRAFT` for validation must not require it to already be executable. The right primitive is one level lower: `(v Version) Parse() (*scenario.Scenario, error)` (`store.go:33`), which `resolveExecutable` itself calls internally (`gate.go:65`) — it converts a specific version's stored artifact straight to a `*scenario.Scenario`, with no lifecycle check at all. The validation orchestrator loads the exact `DRAFT` version by ID and calls `.Parse()` directly, bypassing the gate entirely (correctly — the gate's job is deciding what a *customer* may run, which has nothing to do with factory-internal validation).

### 1.9 No baseline-reset/snapshot-rollback capability exists anywhere
Confirmed by gap analysis: `internal/remediation` is narrowly scoped to one posture-check finding, not a whole-endpoint reset. A persistent lab agent that accumulates state across validation runs is therefore an accepted v1 limitation, not an oversight — see §4.

## 2. Design

### 2.1 A persistent, pre-registered lab agent — not ephemeral provisioning
v1 uses exactly one factory-owned agent, pre-registered the same way any agent is today, marked with a new boolean column (e.g. `is_factory_lab`, migrated via the same idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` pattern already used on `agents`). Ephemeral container/VM provisioning is deferred — only revisited if the persistent agent can't meet isolation/cleanup needs in practice (per explicit direction).

### 2.2 Ownership is enforced at dispatch, not just by convention
A new `dispatchOpts.Mode` value — `"factory-validation"` — is added alongside the existing three. `dispatchRun`'s handling for this mode (a) hard-requires the target agent to carry `is_factory_lab=true`, refusing otherwise even if called with the "right" agent ID by mistake, and (b) skips the customer-specific `ConfirmLab` gate, since there is no customer in this flow. As defense in depth, the three existing customer-facing modes must also refuse a target agent carrying `is_factory_lab=true` — ownership is enforced in both directions, not just named in a comment.

### 2.3 A dispatch-time safety re-check, reusing Phase 4/5's logic unmodified
Immediately before a `"factory-validation"` dispatch is actually sent (inside the same code path added for §2.2, not a separate pre-pass), the existing `safetyVerdict`/`combinatorialRisk` logic is re-invoked against the content version's *current* technique/tactic set. A refusal here writes a fresh `content_safety_verdicts` row (`classifier = "dispatch-recheck"`, reusing the Phase 5 catalog and versioning convention unmodified) documenting why, and the content is sent back to `DRAFT` (§2.5) — nothing is dispatched, no `content_validations` row is written, since no run happened to validate at EXECUTION level.

### 2.4 The validation orchestrator
A new package, `internal/validationlab`, following the same periodic-scan shape as the existing TCV/generation schedulers:

- **Selection:** scans `DRAFT` content versions where `created_by IN ('generator:connector', 'composer:admin')` (§1.7) and not already `VALIDATING`/`VALIDATED`/`REJECTED`.
- **Claim:** calls `Transition(ctx, id, VALIDATING, <system actor>, reason)`. This doubles as the concurrency guard — a candidate another tick (or another orchestrator instance) already claimed simply fails this transition and is skipped, with no separate locking mechanism needed.
- **Safety re-check:** §2.3. A refusal transitions back to `DRAFT` directly from this step.
- **Dispatch:** loads the claimed version and calls `.Parse()` (§1.8) to get a `*scenario.Scenario`, then calls `dispatchRun` with `Mode: "factory-validation"` and the lab agent's ID — reusing the existing parse primitive, not the gate-enforced `ResolveExecutable`, and no new conversion logic. On dispatch failure or skip (agent busy/offline, concurrency limit) before a real `run_id` exists: write `content_validations(level=EXECUTION, outcome=ERROR, run_id=NULL, detail=<failure reason>)` — legal against the CHECK constraint per §1.4 — then `Transition(VALIDATING→DRAFT)`.
- **Observation:** on a successful dispatch, poll `scenario_runs` for that `run_id` with a bounded timeout. This poll is driven by "every row currently `VALIDATING` with a known `run_id`" — not an in-memory list of runs this process instance personally dispatched — so a crash/restart mid-poll naturally resumes rather than orphaning anything (§3, crash recovery).
- **Resolution:** on completion, write `content_validations(level=EXECUTION, outcome=PASS|FAIL, run_id=<real id>, detail=<run summary>)` from the run's actual status/results, then `Transition` to `VALIDATED` (pass) or back to `DRAFT` (fail). On timeout with no completion: `outcome=ERROR`, same transition back to `DRAFT`. A malformed/unparseable `scenario_runs.results` row gets its own `ERROR` outcome for that row only — it never halts the rest of the scan.

### 2.5 Publication gate for TCF-originated content only
For content where `created_by IN ('generator:connector', 'composer:admin')` (§1.7), the direct `DRAFT→PUBLISHED_LOCAL` transition (§1.6) is refused. A new transition, `VALIDATED→PUBLISHED_LOCAL`, is added — still human-actor-gated, matching the existing pattern where a person makes the final publish decision. Validation makes content *eligible*; it does not auto-publish. `RegisterLocalApproved` (§1.6) is completely untouched: its `created_by` is always `ActorIntake`, which never matches the new gate's filter.

## 3. Acceptance criteria

1. `dispatchRun` with `Mode: "factory-validation"` targeting an agent where `is_factory_lab != true` is refused.
2. `dispatchRun` with any of the three existing customer-facing modes targeting the factory-lab agent is refused.
3. Content that passed safety at `Compose`/`RegisterGenerated` time but whose current technique set fails the dispatch-time re-check is refused before dispatch, with a `content_safety_verdicts(classifier="dispatch-recheck")` row whose `detail` is traceable to the actual re-check result — and no `content_validations` row.
4. A successful validation run produces exactly one `content_validations(level=EXECUTION, outcome=PASS, run_id=<real, non-null id>)` row and a `VALIDATING→VALIDATED` transition.
5. A failed run produces `outcome=FAIL` and a `VALIDATING→DRAFT` transition.
6. A dispatch failure with no run ever created produces `outcome=ERROR, run_id=NULL` (verified against the real DB CHECK constraint, not mocked) and `VALIDATING→DRAFT`.
7. A run that never completes within the timeout produces `outcome=ERROR` and `VALIDATING→DRAFT` — content is never left in `VALIDATING` indefinitely.
8. Two concurrent scan ticks (or two orchestrator instances) racing the same `DRAFT` candidate dispatch exactly once.
9. `DRAFT→PUBLISHED_LOCAL` is refused for content where `created_by IN ('generator:connector','composer:admin')`.
10. `RegisterLocalApproved`'s immediate-publish behavior is provably unaffected (regression test).
11. `VALIDATED→PUBLISHED_LOCAL` succeeds for a human actor.
12. A `VALIDATING` row with a real, already-completed `run_id` but no in-memory orchestrator state (simulating a crash/restart) still resolves correctly on the next scan.

## 4. Out of scope (this phase)

- **TELEMETRY/DETECTION-level validation.** `internal/detectverify` is hard-wired to customer SIEM/EDR credentials, architecturally separate from factory-internal infrastructure by design (§1.4). Deferred to a future phase once a factory-side detection target exists.
- **Ephemeral container/VM provisioning.** v1 uses one persistent, pre-registered lab agent (§2.1). Only revisited if that can't meet isolation/cleanup needs in practice.
- **Baseline reset / snapshot rollback between validation runs.** No such capability exists anywhere in this codebase today (§1.9); the persistent lab agent accumulating state across runs is an accepted v1 limitation, not solved here.
- **Retry backoff or an attempt cap for content that keeps failing validation.** Failed content returns to `DRAFT` and is eligible for the very next scan tick with no cooldown — each attempt is still honestly recorded as its own `content_validations` row, so repeated failure is visible, just potentially noisy. Explicitly deferred per direction.
- **Any change to `RegisterLocalApproved` / the operator hand-authored "save" flow.** Stays byte-for-byte unmodified (§1.6, §2.5).
- **Any change to `safetyVerdict`, `combinatorialRisk`, or the Phase 5 tactic-pair catalog.** Reused unmodified (§2.3); the "dispatch-recheck" classifier is a new *label* on the same existing machinery, not new risk logic.

## 5. Review Focus

- A content version dispatched for validation whose current technique set would now fail Phase 5's combinatorial check (e.g. it passed at Compose time under an older catalog version, or its components changed) — confirm refusal before dispatch, with the `content_safety_verdicts` row's `detail` actually traceable, not just its existence.
- A dispatch attempt against the factory-lab agent using one of the three *existing* customer-facing modes — confirm it is refused, proving ownership is enforced in both directions and not just documented.
- A dispatch failure (agent offline/busy) that never produces a `run_id` — confirm the `content_validations` write with `run_id=NULL, outcome=ERROR` actually succeeds against the real database CHECK constraint from `content_registry_schema.go:145`, not a mocked store.
- A `VALIDATING` row whose dispatched run already completed before the orchestrator process restarts — confirm the next scan resolves it correctly using only durable state (`scenario_runs`, `content_versions.state`), with no reliance on in-memory tracking.
- `RegisterLocalApproved`'s existing behavior — confirm this phase's diff does not touch `intake.go:215-253` and a regression test still passes for its immediate-publish path.
