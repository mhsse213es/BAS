# Ransomware Evidence Engine — T1490 Vertical Slice Design

## 1. Context and motivation

Audspect has real ransomware *content*: 6 named-family kill chains (LockBit,
BlackCat/ALPHV, Akira, Play, RansomHub, Cl0p), 2 generic readiness drills
(`ransomware-drill.yaml`, `endpoint-mastery/em-07-ransomware-readiness.yaml`),
13 ransomware-relevant detection profiles, and a UI readiness-score widget
(`orchestrator/web/src/features/ransomware.js`). All of it rides the generic
scenario engine and a naive `pass / (pass + fail)` score.

What's missing is the same thing that was missing for AD and lateral
movement before this session's work on `adprimitive`/`admatrix`/`controlval`
and `latmove`/`latdetect`: an **authoritative evidence layer** that proves
whether a control actually prevented, detected, contained, recovered from,
or protected data against a ransomware behavior — as opposed to a scenario
step merely running and a detection profile merely firing.

This spec covers **one end-to-end vertical slice**: T1490 (Inhibit System
Recovery / VSS & backup-catalog deletion), chosen because it's referenced
across all 7 ransomware scenario files, has one clean, binary postcondition
(did the targeted shadow copies/backup catalog survive the authorized
attempt), and already has real safety precedent in the codebase (Akira's
`BAS_CONFIRM_VSS_DELETE` gate). The goal is to prove the architecture once,
not to retrofit every scenario or build all five capability dimensions.

**Explicitly deferred to later phases** (not scoped here): Containment,
Data Protection, actual restore-testing/RPO-RTO, cross-platform (Linux/ESXi)
adapters, new ransomware family content, and any scoring/weighting UI. The
full 5-dimension / 8-capability vision is recorded in project memory for
traceability but is not part of this slice's deliverable.

## 2. Target architecture (this slice only)

```
Existing scenario/detection content (unchanged)
        |
        v
internal/rwevidence  (new package)
  - Capability, CapabilityResult (shared record)
  - prevention.go  -- adapter to controlval
  - recovery.go    -- T1490's own verification contract
  - detection.go    -- thin wrapper over existing detection-profile result
```

`rwevidence` depends one-way on `controlval` and `adprimitive` (for
`RiskClass`, informational only — this package executes nothing and gates
nothing new). It has zero dependency on `admatrix`, `adcontrolval`,
`latmove`, or `latdetect` — those are different domains; nothing here
reuses their types.

## 3. Prerequisite: `controlval.SkipReason` (Task 0)

Before `rwevidence` is written, `controlval`'s canonical verdict taxonomy
(`PASS`/`FAIL`/`ERROR`/`SKIPPED` — locked earlier this session, reused by
`adcontrolval`/`latmove`/`adefficacy`) gains one additive field:

```go
type SkipReason string
const (
    SkipInsufficientEvidence SkipReason = "insufficient_evidence"
    SkipNotApplicable        SkipReason = "not_applicable"
    SkipNotTested            SkipReason = "not_tested"
)

type Validation struct {
    Verdict    Verdict
    Reason     string
    SkipReason SkipReason `json:"skipReason,omitempty"`
    // ...existing fields unchanged
}
```

This is shared, canonical plumbing — not ransomware-specific — because the
distinction (evidence missing vs. evidence exists-but-inconclusive vs.
genuinely doesn't apply) is a property of the *taxonomy*, not of any one
consumer. No second verdict taxonomy is introduced anywhere.

**Four locked invariants:**
1. `SkipReason` must be empty for `PASS`, `FAIL`, and `ERROR`.
2. `SKIPPED` must always carry one of the three recognized reasons — never
   empty, never silently treated as success.
3. `Evaluate` itself never produces `SkipNotApplicable` — that value is only
   ever set directly by a caller for a capability that was never attempted
   because it doesn't apply to the environment. `Evaluate` only reasons
   about evidence it was handed, never about applicability.
4. Coverage-math rule (**documented here, not implemented in this slice** —
   binding on whoever builds ransomware scoring later): `not_applicable` is
   excluded from both the numerator and denominator of tested-coverage
   math — fully neutral, reported as its own separate count. `not_tested`
   and `insufficient_evidence` remain in the denominator but never count
   toward the "proven" numerator, so they visibly show as gaps and are
   never silently dropped.

**Migration cost, stated explicitly:** `Evaluate` has four existing
`SKIPPED`-producing branches (verified against current source, not assumed):
`obs == nil` ("control response not recorded"), `obs.Outcome ==
OutcomeUnknown`, below-required-confidence-floor, and inferred-only-evidence
cannot-establish-prevention (Invariant A). Only the first (`obs == nil`) is
genuinely "no evaluation was ever attempted" → `SkipNotTested`. The other
three all have *some* evidence that simply doesn't clear the bar → all three
map to `SkipInsufficientEvidence`. Each branch gets its reason tagged at the
branch site. Existing tests in
`controlval_test.go`, and any `adcontrolval`/`latmove`/`adefficacy` test that
asserts exact `Validation` equality on a `Skipped` case, must be updated to
include the now-expected `SkipReason`. Two new invariant tests enforce (1)
and (2): `TestEvaluate_NonSkippedNeverHasSkipReason` and
`TestEvaluate_SkippedAlwaysHasRecognizedReason` (table-driven across every
branch that returns `Skipped`).

## 4. Shared evidence contract

```go
type Capability string
const (
    CapabilityPrevention     Capability = "prevention"
    CapabilityDetection      Capability = "detection"
    CapabilityContainment    Capability = "containment"
    CapabilityRecovery       Capability = "recovery"
    CapabilityDataProtection Capability = "data_protection"
)

type CapabilityResult struct {
    Capability  Capability
    TechniqueID string // e.g. "T1490"
    Verdict     controlval.Verdict
    SkipReason  controlval.SkipReason
    Reason      string
    Provenance  controlval.CorrelationKey // reused, not reinvented
}

type Technique struct {
    ID        string
    Name      string
    MitreID   string
    RiskClass adprimitive.RiskClass // informational only in this package
}

func VSSInhibition() Technique {
    return Technique{
        ID: "vss-inhibition", Name: "Inhibit System Recovery (VSS/Backup Catalog)",
        MitreID: "T1490", RiskClass: adprimitive.RiskPotentiallyDestructive,
    }
}

type AttemptKey struct { RunID string; TechniqueID string }
```

**Locked principle:** the five `Capability` values are *reporting
categories*, not independent execution engines. One technique (T1490) can
and does produce several independently-verified `CapabilityResult`s — this
slice produces three (Prevention, Recovery, Detection) — and none of them is
ever inferred from another. A Prevention PASS must never imply a Recovery
PASS, or vice versa; this is pinned by a dedicated regression test (§8).

`controlval.Validation` stays generic. All T1490-specific shape (the
`VSSInhibition()` technique, `SurvivalResult`, the Recovery contract below)
lives in `rwevidence`, never added to the canonical type.

## 5. Prevention — adapter to `controlval`

```go
func PreventionExpectationFor(tech Technique) controlval.Expectation {
    return controlval.Expectation{
        Expected: controlval.OutcomeBlocked, PolicyVerified: false, MinConfidence: controlval.ConfidenceHigh,
    }
}

func PreventionFromValidation(tech Technique, v controlval.Validation) CapabilityResult {
    return CapabilityResult{
        Capability: CapabilityPrevention, TechniqueID: tech.MitreID,
        Verdict: v.Verdict, SkipReason: v.SkipReason, Reason: v.Reason,
    }
}
```

Goes through the existing `controlval.Evaluate` + `controlval.FakeProvider`
— no new provider machinery. The adapter only translates; it never
recomputes or overrides what `Evaluate` already decided. The expectation:
an authorized test identity's destructive VSS-delete attempt is *expected*
to be `Blocked` by the deployed control.

## 6. Recovery — its own verification contract

```go
type SurvivalResult string
const (
    SurvivalConfirmed     SurvivalResult = "confirmed"     // targeted copies/catalog entries still present
    SurvivalLost          SurvivalResult = "lost"          // confirmed destroyed
    SurvivalIndeterminate SurvivalResult = "indeterminate" // could not verify either way
)

type RecoveryObserver interface {
    ObserveSurvival(ctx context.Context, key AttemptKey) (SurvivalResult, error)
}

// FakeRecoveryObserver is the only implementation in this slice. An
// uncaptured key returns SurvivalIndeterminate -- never guessed Confirmed
// or Lost, same discipline as every other fake this session.
type FakeRecoveryObserver struct {
    Results map[string]SurvivalResult
    Err     map[string]error
}

func RecoveryFromSurvival(tech Technique, result SurvivalResult, corroboratingDetail string) CapabilityResult {
    // SurvivalConfirmed -> Pass; SurvivalLost -> Fail;
    // SurvivalIndeterminate -> Skipped / SkipInsufficientEvidence.
    // corroboratingDetail (the existing windows_vss_inhibition profile's
    // alerts) rides along in Reason as supporting detail ONLY -- it never
    // changes the Verdict by itself, same invariant as DCSync's 4662 and
    // latmove's SecondaryLogObserved.
}
```

Primary evidence is direct enumeration before/after the authorized attempt
— "verify postconditions, not command-success," the same discipline already
applied to DCSync (DRSUAPI-primary) and `latmove` (marker-readback). Every
Recovery `CapabilityResult`'s `Reason` explicitly scopes the claim: *"the
specific shadow copies/backup catalog entries targeted by this authorized
attempt survived/did not survive"* — never phrased in a way a reader could
generalize into "backup systems are recoverable." That broader claim
requires the separate, later Recovery Assurance capability (real restore
testing, RPO/RTO) — explicitly out of scope here.

## 7. Detection — reuse, not rebuild

```go
func DetectionFromProfileResult(tech Technique, profileVerified bool, reason string) CapabilityResult {
    // profileVerified true -> Pass; false with a definitive negative result -> Fail;
    // inconclusive/not-yet-run -> Skipped / SkipInsufficientEvidence or SkipNotTested as appropriate.
}
```

Wraps the existing `windows_vss_inhibition` detection-profile verification
result (already live, Microsoft-Defender auto-verified across all 7
ransomware scenarios) rather than building a new `detectverify`-based bridge
(the `latdetect`/`addetect` pattern) in this pass. A rigorous
alert-latency-measuring `rwdetect` package is a clean, separable follow-up
once Prevention and Recovery are proven — not required to validate the
capability-independence architecture this slice exists to prove.

## 8. Testing strategy / exit criterion

- `controlval`: Task 0's two new invariant tests, plus every existing
  `Skipped`-asserting test across `controlval`, `adcontrolval`, `latmove`,
  `adefficacy` updated with its now-expected `SkipReason`. Full suite green.
- `rwevidence`: unit tests for `PreventionExpectationFor`/
  `PreventionFromValidation`, `FakeRecoveryObserver`/`RecoveryFromSurvival`
  (including the Confirmed/Lost/Indeterminate truth table), and
  `DetectionFromProfileResult`.
- One end-to-end test: given a single `AttemptKey` for `VSSInhibition()`,
  all three capability paths (Prevention via a `controlval.FakeProvider`,
  Recovery via `FakeRecoveryObserver`, Detection via a canned profile
  result) independently produce a `CapabilityResult`, all three sharing one
  `CorrelationKey`.
- The independence regression test named in §4: construct a case where
  Prevention is `PASS` and Recovery is `FAIL` (or vice versa) and assert
  neither `CapabilityResult` is silently coerced to match the other.
- `go vet`/`gofmt`/`go build ./...` clean across touched packages.

**Exit criterion:** the three capability results for T1490 are each
independently, correctly derived and never cross-inferred; the canonical
verdict taxonomy gained `SkipReason` without breaking any existing
consumer; nothing in this slice executes anything or claims real evidence
— it is lab-independent and fake-backed, same as every other vertical this
session, with real observers explicitly deferred.
