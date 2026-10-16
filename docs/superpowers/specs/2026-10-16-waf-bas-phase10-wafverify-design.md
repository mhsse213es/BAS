# WAF BAS Mastery Phase 10: Independent Verification and Continuous Mastery — Design Spec

## 1. Scope

Per `waf.txt` lines 181-184, Phase 10 (the final phase of the 10-phase roadmap) is: **"Independent verification and continuous mastery — Add regression suites, vendor/version benchmarks, finding reproduction, remediation retests, and coverage-quality gates."**

Unlike every attack-content phase (2, 5, 6, 7) or the detection-pipeline phase (8) or the compliance-bundling phase (9), Phase 10 is a **meta-validation layer over the testing program itself**: it takes `wafval.Verdict` values already produced by any other phase's evaluation and asks process-level questions — did a result stay stable over time, how do two vendors/versions compare, can a finding be reproduced, did a remediation actually work, and is the program's own test coverage good enough. New package: `orchestrator/internal/wafverify`.

Five named items map 1:1 onto five evaluation shapes and five seed scenarios:

| Named item | Shape | Seed ID |
|---|---|---|
| regression suites | ranked verdict comparison (stability over time) | WAFVERIFY-001 |
| vendor/version benchmarks | ranked verdict comparison (cross-vendor) | WAFVERIFY-002 |
| finding reproduction | equality check (no ranking) | WAFVERIFY-003 |
| remediation retests | ranked verdict comparison (before/after a fix) | WAFVERIFY-004 |
| coverage-quality gates | ratio-against-threshold check | WAFVERIFY-005 |

## 2. Dependency

`wafverify` depends on `internal/wafval` only (`Verdict` and its constants) plus stdlib `fmt`. It does not depend on `wafcatalog`, `wafpolicygap`, `wafevasion`, `wafapiflow`, `wafbotabuse`, `waforigin`, `wafdetection`, or `wafprofile` — this phase is generic over any already-computed `wafval.Verdict`, regardless of which attack vector, evasion technique, or profile produced it, so it needs no cross-reference into any of those catalogs. This mirrors `wafdetection`'s (Phase 8) precedent of being the only other phase with zero catalog cross-reference.

## 3. A shared, deliberately scoped primitive: ranking `wafval.Verdict`

Three of the five shapes (regression, benchmark, remediation) need to answer "did this verdict get better or worse than that one," which requires an ordering. `wafval.Verdict` has no built-in ordering, and none is added to `wafval` itself (per the zero-new-wafval-logic discipline established in Phase 8's spec §8 and reused here). Instead, `wafverify` defines a private ranking scoped explicitly to `ClaimPrevention`-shaped verdicts, the common case across every attack-content phase:

```go
func verdictRank(v wafval.Verdict) (rank int, ok bool) {
    switch v {
    case wafval.VerdictMissed:
        return 0, true
    case wafval.VerdictDetectedButAllowed:
        return 1, true
    case wafval.VerdictBlocked:
        return 2, true
    default:
        return 0, false
    }
}
```

`wafval.VerdictAllowed`, `wafval.VerdictIncorrectlyBlocked` (both `ClaimFalsePositive`-shaped), and `wafval.VerdictInconclusive` are deliberately **not ranked** — mixing a false-positive claim's "better" direction (toward `Allowed`) with a prevention claim's "better" direction (toward `Blocked`) on one scale would conflate two different claim types, the same category of mistake `wafevasion`'s `decideEvasionGap` and `waforigin`'s `decideOriginGap` were careful to avoid in earlier phases. Any ranked comparison given an unrankable verdict on either side resolves to that shape's `Inconclusive` outcome — never a guessed direction.

**Finding reproduction (shape 3) does not use this ranking at all.** Reproducibility is a question of exact equality ("did we get the same answer again"), not of direction, so it applies uniformly to any verdict, including `ClaimFalsePositive`-shaped ones.

## 4. Types

### 4.1 Regression (shape 1)

```go
type RegressionScenario struct { ID, Description, Provenance string }
func NewRegressionScenario(id string, description string, provenance string) (RegressionScenario, error)

type RegressionStatus string
const (
    RegressionStable       RegressionStatus = "stable"
    RegressionImproved     RegressionStatus = "improved"
    RegressionRegressed    RegressionStatus = "regressed"
    RegressionInconclusive RegressionStatus = "inconclusive"
)
func EvaluateRegression(scenario RegressionScenario, baseline wafval.Verdict, current wafval.Verdict) (RegressionStatus, string, error)
```
Logic: rank both; either unrankable → `RegressionInconclusive`. `current` rank `<` `baseline` rank → `RegressionRegressed`; `>` → `RegressionImproved`; `==` → `RegressionStable`.

### 4.2 Benchmark (shape 2)

```go
type BenchmarkScenario struct { ID, Description, Provenance string }
func NewBenchmarkScenario(id string, description string, provenance string) (BenchmarkScenario, error)

type VendorResult struct { Vendor, Version string; Verdict wafval.Verdict }
func NewVendorResult(vendor string, version string, verdict wafval.Verdict) (VendorResult, error)

type BenchmarkOutcome string
const (
    BenchmarkStronger      BenchmarkOutcome = "stronger"
    BenchmarkWeaker        BenchmarkOutcome = "weaker"
    BenchmarkTied          BenchmarkOutcome = "tied"
    BenchmarkInconclusive  BenchmarkOutcome = "inconclusive"
)
func EvaluateBenchmark(scenario BenchmarkScenario, a VendorResult, b VendorResult) (BenchmarkOutcome, string, error)
```
`NewVendorResult` validates `vendor`/`version` non-empty. `EvaluateBenchmark` ranks `a.Verdict` and `b.Verdict`; either unrankable → `BenchmarkInconclusive`; `a` ranks higher → `BenchmarkStronger`; lower → `BenchmarkWeaker`; equal → `BenchmarkTied`. `BenchmarkStronger`/`Weaker` describe `a` relative to `b` — the reason string names both vendors so the direction is never ambiguous from the outcome alone.

### 4.3 Reproduction (shape 3)

```go
type ReproductionScenario struct { ID, Description, Provenance string }
func NewReproductionScenario(id string, description string, provenance string) (ReproductionScenario, error)

type ReproductionStatus string
const (
    ReproductionConfirmed    ReproductionStatus = "confirmed"
    ReproductionNotConfirmed ReproductionStatus = "not_confirmed"
    ReproductionInconclusive ReproductionStatus = "inconclusive"
)
func EvaluateReproduction(scenario ReproductionScenario, original wafval.Verdict, attempt wafval.Verdict) (ReproductionStatus, string, error)
```
Logic (no ranking): either `original == wafval.VerdictInconclusive` or `attempt == wafval.VerdictInconclusive` → `ReproductionInconclusive` (an inconclusive original finding has nothing to reproduce; an inconclusive reproduction attempt can't confirm or deny). Otherwise `original == attempt` → `ReproductionConfirmed`; else → `ReproductionNotConfirmed`.

### 4.4 Remediation (shape 4)

```go
type RemediationScenario struct { ID, Description, Provenance string }
func NewRemediationScenario(id string, description string, provenance string) (RemediationScenario, error)

type RemediationStatus string
const (
    RemediationFixed       RemediationStatus = "fixed"
    RemediationUnchanged   RemediationStatus = "unchanged"
    RemediationRegressed   RemediationStatus = "regressed"
    RemediationInconclusive RemediationStatus = "inconclusive"
)
func EvaluateRemediation(scenario RemediationScenario, baseline wafval.Verdict, retest wafval.Verdict) (RemediationStatus, string, error)
```
Logic (ranked, like Regression): either unrankable → `RemediationInconclusive`. `retest` rank `>` `baseline` rank → `RemediationFixed`; `<` → `RemediationRegressed`; `==` → `RemediationUnchanged` (deliberately not named "StillBroken": if `baseline` was already `VerdictBlocked`, an unchanged retest is not "broken," so a neutral label is used regardless of which rank the pair sits at).

### 4.5 Coverage gate (shape 5)

```go
type CoverageGateScenario struct { ID, Description, Provenance string; MinimumCoverage float64 }
func NewCoverageGateScenario(id string, description string, provenance string, minimumCoverage float64) (CoverageGateScenario, error)

type CoverageGateStatus string
const (
    CoverageGatePass         CoverageGateStatus = "pass"
    CoverageGateFail         CoverageGateStatus = "fail"
    CoverageGateInconclusive CoverageGateStatus = "inconclusive"
)
func EvaluateCoverageGate(scenario CoverageGateScenario, totalScenarios int, exercisedScenarios int) (CoverageGateStatus, string, error)
```
`NewCoverageGateScenario` validates `id`/`description`/`provenance` non-empty and `minimumCoverage` in `[0.0, 1.0]`. `EvaluateCoverageGate` returns an error (not a status) if `exercisedScenarios < 0` or `exercisedScenarios > totalScenarios` (an invalid count pair, a caller bug, not a measurable outcome); `totalScenarios <= 0` → `CoverageGateInconclusive, nil` (nothing to measure, not an error, since a catalog of size zero is a real albeit degenerate state, not a malformed call). Otherwise computes `ratio := float64(exercisedScenarios) / float64(totalScenarios)`; `ratio >= scenario.MinimumCoverage` → `CoverageGatePass`; else `CoverageGateFail`.

## 5. Seed catalog

```go
func AudspectWAFVerifyCatalog() (regression []RegressionScenario, benchmark []BenchmarkScenario, reproduction []ReproductionScenario, remediation []RemediationScenario, coverageGate []CoverageGateScenario, err error)
```

Exactly 5 scenarios, one per shape, one per named item: WAFVERIFY-001 (regression), WAFVERIFY-002 (benchmark), WAFVERIFY-003 (reproduction), WAFVERIFY-004 (remediation), WAFVERIFY-005 (coverage gate, with a representative `MinimumCoverage` of `0.8`).

## 6. Acceptance gate

1. `verdictRank` ranks exactly `VerdictMissed` (0) `< VerdictDetectedButAllowed` (1) `< VerdictBlocked` (2), and is unranked (`ok == false`) for `VerdictAllowed`, `VerdictIncorrectlyBlocked`, and `VerdictInconclusive`.
2. `EvaluateRegression` returns `RegressionInconclusive` when either verdict is unrankable, `RegressionRegressed`/`RegressionImproved` for a rank decrease/increase, and `RegressionStable` for no change — including the degenerate case of two identical unrankable-category calls being inconclusive rather than "stable by default."
3. `NewVendorResult` rejects empty `vendor`/`version`. `EvaluateBenchmark` returns `BenchmarkInconclusive` when either side is unrankable, and correctly resolves `BenchmarkStronger`/`BenchmarkWeaker`/`BenchmarkTied` otherwise, with the reason string naming both vendors.
4. `EvaluateReproduction` returns `ReproductionInconclusive` when either side is `VerdictInconclusive`, and otherwise resolves `ReproductionConfirmed`/`ReproductionNotConfirmed` purely by equality — including for `ClaimFalsePositive`-shaped verdicts, which `EvaluateRegression`/`EvaluateBenchmark`/`EvaluateRemediation` cannot handle.
5. `EvaluateRemediation` mirrors `EvaluateRegression`'s ranked logic but names its equal-rank outcome `RemediationUnchanged`, not an implied-broken label.
6. `NewCoverageGateScenario` rejects a `minimumCoverage` outside `[0.0, 1.0]`. `EvaluateCoverageGate` errors on `exercisedScenarios < 0` or `exercisedScenarios > totalScenarios`; returns `CoverageGateInconclusive` (not an error) for `totalScenarios <= 0`; and otherwise compares the ratio against the threshold correctly, including the exact-equality boundary (`ratio == minimumCoverage` → `CoverageGatePass`).
7. `AudspectWAFVerifyCatalog` returns exactly 5 scenarios, one per shape, each constructing without error.

## 7. Deferred (explicitly)

- Any real cross-run persistence or historical storage of verdicts over time — every shape here takes caller-supplied `wafval.Verdict` values directly; there is no database, file, or time-series store. "Over time"/"before/after" is expressed purely as two function arguments.
- Ranking for `ClaimFalsePositive`-shaped verdicts (`VerdictAllowed`/`VerdictIncorrectlyBlocked`) in the Regression/Benchmark/Remediation shapes — deliberately out of scope per §3; Reproduction already covers them via equality.
- Any dependency on `wafcatalog` or a per-attack-vector cross-reference, consistent with this being the second (after `wafdetection`) fully attack-agnostic phase.
- Expanding the seed catalog beyond 1 scenario per named item.
- Any new `wafval` logic — this phase reads `wafval.Verdict` values and constants only; it adds no method to `wafval` itself.

This is the final phase of the `waf.txt` 10-phase roadmap.
