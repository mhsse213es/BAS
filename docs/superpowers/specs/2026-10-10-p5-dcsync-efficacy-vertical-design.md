# Phase 5 — First Real Control-Efficacy Vertical: DCSync — Design Spec

**Date:** 2026-10-10
**Status:** Approved for planning (user scoped and locked the slice; authorized scope→spec→plan→implement without an intermediate gate).
**Builds on:** `2026-10-10-control-efficacy-validation-design.md` (the generic layer), `2026-10-10-p5-ad-lab-substrate-hyperv-design.md` + `docs/operations/p5-ad-lab-operator-runbook.md` (the controlled lab).

## 1. Scope

Prove **one** control-efficacy result end-to-end: does AD's **native directory-replication-rights control** prevent **DCSync** by an unauthorized principal? This is the first *real* provider (a native AD control, not a vendor), chosen because every other piece already exists — the `dcsync` primitive (`adprimitive.DCSyncCatalog`, `T1003.006`), the `dc-only` lab, and the two identities already in the runbook.

Two principals, run as a pair in the same lab build:
- **`LAB\labuser` — negative control.** No replication rights → DCSync should be **denied**. Expected outcome `blocked`.
- **`LAB\attacker` — positive control.** Replication rights deliberately granted (existing lab config) → DCSync should **succeed**. Expected outcome `allowed`. Its job is to prove the harness *can* succeed, so a denial of `labuser` is trustworthy.

The "control" is AD's own DACL enforcement of `DS-Replication-Get-Changes[-All]`. No vendor, no agent.

### Non-goals / build boundary

- **No live execution-path wiring.** Nothing touches `dispatchRun` or `admatrix.CapabilityStates()`. The efficacy axis stays `Evaluated=false` in live output until a real lab run is authorized.
- **No real `ControlDecisionSource`.** Only a fake ships. The real source (reading the DC via `adlabhyperv`) is lab-gated.
- **No general-purpose AD policy framework, no vendor adapter.** Thin vertical only.
- **Future verticals, NOT built here:** deny-network-logon GPO, Protected Users blocking NTLM, Authentication Policy Silo. Recorded as the next controls once this vertical is proven.

## 2. Evidence model (the heart of the slice)

Two evidence items, with a strict hierarchy:

- **Primary — DRSUAPI result.** The directory replication call's own outcome is the **sole determinant of the control Outcome**:
  - `access_denied` → `OutcomeBlocked`
  - `succeeded` (replication returned secrets) → `OutcomeAllowed`
  - `indeterminate` (no conclusive call result) → `OutcomeUnknown`
- **Secondary — Windows Security event 4662 (directory-object access).** Corroboration **only**. It may be recorded as supporting detail, but:
  - 4662 presence alone **never** establishes `Blocked` (or any outcome). An `indeterminate` DRSUAPI with a present 4662 stays `OutcomeUnknown`.
  - A 4662 event is **not** assumed to mean success or failure; it is interpreted alongside the DRSUAPI result, never in place of it.

`EvidenceKind` is always `observed` (the DC's own call result is a direct observation, not inference).

**Confidence mapping** (`confidenceFor`), tuned so a conclusive, correlated primary result is authoritative on its own (DRSUAPI is primary):
- not correlated to this run/target/action → `ConfidenceNone` (→ `SKIPPED`)
- DRSUAPI `indeterminate` → `ConfidenceNone` (outcome `Unknown` → `SKIPPED`)
- correlated + DRSUAPI conclusive → `ConfidenceHigh` (the 4662 corroboration state is recorded in `Detail`; its absence does **not** lower confidence, because DRSUAPI is the authoritative primary signal)

This clears the locked strict floor (unset `MinConfidence` → high): a conclusive, correlated DRSUAPI result yields a determinate verdict; anything short of that fails closed to `SKIPPED`.

## 3. The two expectations

Declared per principal (per-case expectation, no policy engine). `PolicyVerified` is **false** — the grant/absence is the lab's *intended* configuration, supplied as test input, not independently verified by this test.

- **Negative (`labuser`):** `Expected = blocked`, `MinConfidence = high`, `PolicyBasis = "LAB\labuser holds neither DS-Replication-Get-Changes nor -All on the domain head"`.
- **Positive (`attacker`):** `Expected = allowed`, `MinConfidence = high`, `PolicyBasis = "LAB\attacker deliberately granted DS-Replication-Get-Changes[-All] (positive control)"`.

## 4. Independence + trust pairing

The two principals' results are **independent evidence** — each graded by `controlval.Evaluate` from its own observation, neither reading the other.

A separate, explicit **acceptance gate** applies the runbook's trust rule without mutating raw evidence:

> A negative-control denial is only trustworthy once the harness is shown capable of an authorized success.

`Pair.AcceptedNegativeVerdict()` returns the *reportable* negative verdict: if the raw negative verdict is `PASS` **but** the positive control did not cleanly `PASS`, it is downgraded to `SKIPPED` (reason: harness not shown capable of success). It never upgrades anything, and never touches the two raw `Validation` values. This keeps evidence independent while preventing a broken harness from manufacturing a trustworthy PASS.

## 5. Package layout & dependencies

```
internal/adefficacy    new, thin vertical. Imports controlval + adcontrolval + adprimitive (+ stdlib).
                       No adlabrt import (correlation uses runID/target strings); no vendor; no DB.
```

- `provider.go`: `DRSUAPIResult`, `Corroboration`, `ControlDecision`, `ControlDecisionSource` (the seam), `NativeADProvider` (implements `controlval.Provider`), `confidenceFor`.
- `dcsync.go`: `NegativeExpectation()`, `PositiveExpectation()`, principal constants, `KeyFor(runID, target, window)` (via `adcontrolval.CorrelationKeyFor` over the real `dcsync` primitive), `Pair` + `AcceptedNegativeVerdict()`.
- Tests + a fake `ControlDecisionSource`.

`controlval`, `adcontrolval`, `admatrix` gain nothing and do not import `adefficacy`.

## 6. Lab-gated boundary & readiness

The real result requires the operator to stand up the `dc-only` lab (runbook) and a real `ControlDecisionSource` that reads the DC's DRSUAPI result + 4662 for each run. Readiness (adds to the runbook's §8):
1. `dc-only` lab up and isolation-verified (runbook §4).
2. `LAB\attacker` granted the two replication rights; `LAB\labuser` granted none (runbook §3.3) — the positive/negative pair.
3. A real `ControlDecisionSource` returning the DRSUAPI result (primary) + 4662 (corroboration), correlated to each run.
4. Operator authorization bound to the run (`adgate`).
5. Both principals executed **in the same lab build**; the negative PASS accepted only if the positive PASSed.

Until then: `adefficacy` is fake-backed only; the axis is unevaluated live.

## 7. Definition of done

A reproducible lab procedure that:
- executes DCSync for **both** principals and produces **evidence-backed** results (DRSUAPI primary + 4662 corroboration);
- maps each result through `controlval.Evaluate` and `adcontrolval` to the efficacy axis;
- yields `labuser → blocked/PASS` only when `attacker → allowed/PASS` in the same build;
- leaves the result **`SKIPPED` (never PASS)** whenever evidence is incomplete or ambiguous (uncorrelated, indeterminate DRSUAPI, or 4662-only), so no false protection claim is possible;
- performs **no** live `CapabilityStates()`/`dispatchRun` wiring and ships **no** real source.

## 8. Testing

Contract tests (TDD), fake-backed:
- `NativeADProvider.Observe`: `access_denied`→blocked/high; `succeeded`→allowed/high; `indeterminate`→unknown; **4662-present-but-DRSUAPI-indeterminate → unknown (not blocked)**; uncorrelated → none-confidence; source error → propagated (→ ERROR via Evaluate).
- End-to-end per principal: fake decision → Observe → Evaluate → expected verdict (labuser blocked→PASS; labuser allowed→FAIL gap; attacker allowed→PASS).
- Fail-closed: indeterminate/uncorrelated/4662-only → `SKIPPED`.
- Pairing: negative PASS + positive not-PASS → `AcceptedNegativeVerdict` is `SKIPPED`; raw negative `Validation` untouched; negative PASS + positive PASS → negative accepted as `PASS`.
- Mapping: `adcontrolval.ToEfficacyState` of each verdict is faithful (reuses the existing bridge; no new mapping).
