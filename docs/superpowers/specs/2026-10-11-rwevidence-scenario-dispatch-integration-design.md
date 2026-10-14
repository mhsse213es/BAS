# rwevidence Scenario-Dispatch Integration — Design

## Why

`rwevidence` (Prevention/Recovery/Detection/DataProtection/Containment, all 5
capabilities, 3 techniques: T1490/T1486/T1567.002) has never been invoked
outside its own package. This is true of every "mastery" evidence engine in
the codebase today — `controlval`, `adcontrolval`, `adefficacy`, `latmove`
are equally unwired. This sub-project is the first one: it proves the
dispatch-to-evidence integration pattern other initiatives can later follow.

This is sub-project #1 of the ransomware-mastery master roadmap (see
conversation; the other 9 sub-projects are out of scope here). It is
**plumbing, not technique expansion**: it does not add new techniques, real
observers, or scoring/UI. T1/T2 (real-observer wiring, gated on external lab
infrastructure the user is still provisioning) are explicitly out of this
sub-project's critical path.

## Scope

The 8 existing ransomware scenarios/drills:
`akira-kill-chain.yaml`, `blackcat-kill-chain.yaml`, `clop-kill-chain.yaml`,
`lockbit-kill-chain.yaml`, `play-kill-chain.yaml`, `ransomhub-kill-chain.yaml`,
`ransomware-drill.yaml`, `endpoint-mastery/em-07-ransomware-readiness.yaml`.

- **Modeled**: T1490, T1486, T1567.002 — their qualifying attempt steps
  produce real `rwevidence.CapabilityResult`s through the canonical,
  fake-backed evaluators that already exist.
- **Everything else**: every other technique-tagged step across all 8 files
  is explicitly accounted for as not-tested (never silently dropped, never
  given invented capability applicability).
- **Out of scope**: new technique mappings, real observers, scoring
  aggregation, UI. `scenario.Outcome` (the existing pass/fail/error/skipped
  model driving today's legacy display) is read, never modified.

## B. Step classification

For every technique-tagged step, in order:

1. **Is the technique modeled?** Not in {T1490, T1486, T1567.002} →
   every capability gets `SKIPPED`/`not_tested`, specific_reason
   `technique_not_mapped`. Stop here.
2. **Is this step an attempt, or reconnaissance?** A modeled technique's
   step that only enumerates/observes (e.g. "VSS Snapshot Enumeration") is
   not an attempt — no Prevention/Recovery/Detection call fits what it did.
   Every capability gets `SKIPPED`/`not_tested`, specific_reason
   `not_an_attempt`. Stop here.
3. **Did the attempt actually run?** Match the step's *actual output*
   against the known safety-gate pattern for that technique (today: T1490's
   `BAS_CONFIRM_VSS_DELETE not set` marker) — never a blanket
   "any SKIPPED outcome on this step = gate". A gate match →
   `SKIPPED`/`not_tested`, specific_reason `gate_not_confirmed`.
   A *different* unexecuted-precondition case (confirmed in real content:
   `akira-kill-chain.yaml`'s `"no C: VSS shadow copies exist"`) is not a
   safety gate — it's a missing target to test against. That gets its own
   specific_reason, `no_target_precondition`. Any other SKIPPED output this
   sub-project doesn't recognize falls back conservatively to
   `not_tested`/`skip_unclassified` — never guessed into `gate_not_confirmed`.
4. **The attempt ran.** Evaluate the *complete* set of capabilities the
   technique's existing applicability rules define — not just whichever one
   happens to produce a result. For each capability:
   - Applicable, evaluator invoked → whatever verdict the evaluator already
     returns (PASS/FAIL/ERROR, or SKIPPED/insufficient_evidence) — this is
     an **evaluated** result, not a coverage gap. ERROR here (evaluator ran
     and failed operationally) is NOT the same as not-tested (evaluator
     never invoked) — kept distinct.
   - Not applicable under the existing rule (e.g. T1490 has no
     Containment/DataProtection) → `SKIPPED`/`not_applicable`
     (`rwevidence.NotApplicable`, already exists).
   - **Applicability not yet decided** — found during self-review: only
     T1490 has all 5 capabilities' applicability decided in existing code.
     T1486 has no DataProtection ruling. T1567.002 has no Prevention,
     Recovery, or Detection ruling (only DataProtection and Containment
     exist for it). This is 4 real gaps, not an oversight to paper over:
     this sub-project does **not** invent those 4 rulings (that's a
     modeling judgment call, out of scope here, same as the prohibition on
     inventing applicability for unmodeled techniques). Each of those 4
     (technique, capability) pairs gets `SKIPPED`/`not_tested`,
     specific_reason `applicability_undecided` — distinct from both
     `not_applicable` (a decided "no") and `technique_not_mapped` (the
     technique itself isn't modeled at all; here it is, just not this
     capability).

No new result-state column. Everything above is expressed through the
existing canonical `Verdict`/`SkipReason` pair, enforced by
`controlval.ValidSkipPair` exactly as it is today. The only schema addition
is a `specific_reason` short machine-readable code — distinct from the
existing free-text `Reason` — purely so a coverage query can `GROUP BY`
verdict/skip_reason/specific_reason without parsing prose:

| Situation | Verdict | skip_reason | specific_reason |
|---|---|---|---|
| Evaluated | PASS/FAIL/ERROR/SKIPPED | per evaluator | evaluator-specific (may be empty) |
| Not applicable | SKIPPED | not_applicable | the applicability rule's own short name |
| Technique not modeled | SKIPPED | not_tested | technique_not_mapped |
| Reconnaissance, not an attempt | SKIPPED | not_tested | not_an_attempt |
| Safety gate not confirmed | SKIPPED | not_tested | gate_not_confirmed |
| No viable target | SKIPPED | not_tested | no_target_precondition |
| Unrecognized skip | SKIPPED | not_tested | skip_unclassified |
| Capability applicability not yet decided for this technique | SKIPPED | not_tested | applicability_undecided |

## C. Identity: `AttemptKey` gains `Action`

Real content breaks `{RunID, TechniqueID}`: `em-07` has three distinct T1490
steps (shadow-copy deletion, `wbadmin` catalog deletion, `bcdedit` disable)
that must never collapse into one Recovery verdict.

- Add `Action string` to `rwevidence.AttemptKey`, mirroring
  `controlval.CorrelationKey.Action` (same reason it exists there).
- `Action` = `scenario.TaskID(step.TechniqueID, step.Name)` — confirmed
  deterministic (`sha256(techniqueID|name)[:8]`) and already
  collision-handled by the existing `dedupeStepIdentity` (two steps sharing
  an identical technique+name pair get disambiguated upstream, before this
  integration ever sees them) — reused, not reinvented.
- `recoveryKey`/`containmentKey` (the `FakeRecoveryObserver`/
  `FakeContainmentObserver` internal key-building helpers) change format to
  include Action. Internal implementation detail, not a public contract —
  every existing test that constructs an `AttemptKey` literal gets updated
  as part of this work (empty-string Action on an old test literal still
  behaves correctly; it just means "this test doesn't care about
  per-action disambiguation", which remains true for all of them).

## D. Dispatch integration point

Additive, called once per technique-tagged step **after** the step's
existing `scenario.Outcome` is computed — never replaces it, never read by
it. A new function, `rwevidence.EvaluateStep(step, result) []CapabilityResult`,
applies the B rules and returns the complete set of rows for that step
(one per applicable capability, `not_applicable` rows included for
completeness per rule 4). The existing legacy pass/(pass+fail)% display
keeps working off `scenario.Outcome` exactly as today; this sits beside it.

## E. Persistence

```sql
CREATE TABLE IF NOT EXISTS rw_capability_results (
  id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
  run_id          text        NOT NULL,
  action          text        NOT NULL,   -- scenario.TaskID(technique_id, step.Name)
  technique_id    text        NOT NULL,
  capability      text        NOT NULL,   -- prevention/detection/containment/recovery/data_protection
  verdict         text        NOT NULL CHECK (verdict IN ('PASS','FAIL','ERROR','SKIPPED')),
  skip_reason     text        CHECK (skip_reason IN ('insufficient_evidence','not_applicable','not_tested')),
  specific_reason text        NOT NULL DEFAULT '',  -- see table in section B; machine code, not prose
  reason          text        NOT NULL DEFAULT '',  -- existing CapabilityResult.Reason, human-readable
  simulated       boolean     NOT NULL DEFAULT true,
  provenance      jsonb,
  created_at      timestamptz NOT NULL DEFAULT NOW(),

  CONSTRAINT rw_capres_skip_ck CHECK (
    (verdict = 'SKIPPED' AND skip_reason IS NOT NULL) OR
    (verdict <> 'SKIPPED' AND skip_reason IS NULL)),
  CONSTRAINT rw_capres_identity UNIQUE (run_id, action, capability)
)
```

- `rw_capres_skip_ck` mirrors `controlval.ValidSkipPair` at the database
  level, same invariant, enforced twice (application code via
  `CapabilityResult.Valid()` before any write, and the DB as the backstop).
- `rw_capres_identity` is the uniqueness rule rule B/C implies, now actually
  enforced, not just described.
- **Retries**: the write is an upsert (`INSERT ... ON CONFLICT (run_id,
  action, capability) DO UPDATE SET ...`) keyed on the same unique
  constraint. A retried step overwrites its own prior row rather than
  duplicating it — correct here because, unlike `verification_history`
  (a multi-entry manual-review audit trail by design), one (run, action,
  capability) has exactly one current automated evaluation; there is no
  multi-version history requirement for this table.
- `simulated` defaults `true`. **Nothing in this sub-project ever writes
  `false`** — that only happens once a real observer (T1/T2, out of scope
  here) backs a result.

## F. Failure-visibility contract

Additive does not mean best-effort-and-silent:

- An evidence-persistence failure **must not** alter or roll back the
  already-computed legacy `scenario.Outcome` — these are two independent
  writes to two independent systems.
- It **must** surface through an explicit error return from the
  integration call, logged by the dispatcher (not swallowed).
- A failed write is never reported as "evidence recorded" anywhere.
- The coverage query (section G) is itself the mechanism that keeps a run
  from being represented as having complete evidence coverage when a
  write failed: a technique-tagged step with zero rows for its expected
  capability set reads as an open gap, not as "nothing happened."

## G. Coverage accounting

A read-only aggregate query: for a given run, `COUNT(*) GROUP BY
technique_id, capability, verdict, skip_reason, specific_reason`. Data only
— no UI (that's sub-project #3). Lets a caller distinguish a technique-level
coverage gap (`technique_not_mapped`) from an individual capability
evaluation gap (e.g. one capability `not_applicable` while its siblings are
genuinely evaluated for the same action).

## Acceptance tests (exit criterion)

1. All 8 scenarios dispatch through this integration with zero errors.
2. Every technique_id appearing across all 8 files has 100% of its
   technique-tagged steps accounted for — a test enumerates every
   technique_id found in the real YAML corpus and asserts none are silently
   missing from the result set (modeled or not).
3. `em-07`'s three distinct T1490 steps each produce independent Recovery
   results (the Action-identity fix, pinned directly against real content).
4. `akira-kill-chain.yaml`'s two distinct T1490 skip patterns
   (`gate_not_confirmed` vs. `no_target_precondition`) are classified
   correctly and differently — not collapsed into one generic skip.
5. A `SKIPPED` legacy outcome never produces a `PASS` capability verdict
   anywhere downstream (the named safety-gate-integrity test).
6. For a qualifying T1490/T1486/T1567.002 attempt step, the *complete*
   applicable capability set is persisted — including `not_applicable`
   rows for capabilities that don't apply — never just whichever capability
   happened to return something.
7. An evaluator-ERROR result and a never-invoked (`not_tested`) result are
   provably distinguishable in the persisted rows (not just in comments).
8. A simulated DB write failure: `scenario.Outcome` is unchanged, the
   integration surfaces an error, and the coverage query reflects the gap
   (not "complete").
9. A retried write for the same `(run_id, action, capability)` does not
   duplicate a row.
10. Every row written by this sub-project has `simulated = true`.
11. T1486's DataProtection row and T1567.002's Prevention/Recovery/Detection
    rows are `SKIPPED`/`not_tested`/`applicability_undecided` wherever their
    steps qualify as an attempt — never silently absent, and never
    defaulted to `not_applicable` (which would assert a decided "no" that
    was never actually made).
