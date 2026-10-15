# WAF BAS Mastery Phase 1: Vendor-Neutral Capability Model & Evidence Contract — Design Spec

## 1. Goal

Phase 1 is the first slice of the WAF BAS Mastery roadmap (`waf.txt`, §6, "The first engineering decision"). It builds the **vendor-neutral capability model and evidence contract** that every later WAF phase depends on, and proves that contract end-to-end against a controlled lab before any attack-payload library is built.

The decision carried in from brainstorming is **hybrid**: lab-first execution against deterministic ground truth, with a domain model whose contracts never assume Audspect owns the WAF, the application, the logs, or the infrastructure. Phase 1 delivers the vendor-neutral domain package (`internal/wafval`) and the lab adapter that produces evidence for it; it does **not** deliver any commercial WAF vendor adapter (AWS WAF, Cloudflare, F5, Imperva, Akamai), and does **not** enable any customer-targeted execution. Customer-facing execution is gated behind a separate readiness project (authorization, bounded execution, vendor-specific evidence collection, deployment safety) that is out of scope here.

The core discipline, stated once: **what the WAF reported is not the same as what happened to the request, and an absence of evidence is not evidence of absence.** A 403 alone does not prove the WAF blocked a request; a 200 alone does not prove a vulnerability was exploitable; a missing log event does not prove a missed detection unless the search was verified complete against a reachable source. Every structure in this spec exists to keep those distinctions from collapsing.

## 2. Scope Boundary

| Component | Phase 1 decision |
|---|---|
| Capability model | Build vendor-neutral |
| Evidence contract | Build vendor-neutral; preserve provenance |
| Verdict engine | Implement and test against multiple evidence sources |
| Test environment | Controlled application + ModSecurity / OWASP CRS |
| Policy weaknesses proven | Managed-rule enforcement, exclusions, detection-only vs. blocking |
| Vendor adapters | Lab adapter only |
| Customer deployment | Architecture-ready, not production-enabled |
| Attack library | Only the minimum tests required to prove the first slice |

## 3. Why a New Package, and Why Not `controlval`

`internal/controlval` is the product-neutral control-efficacy model built for the AD vertical (`adefficacy`). It already proves three patterns this phase reuses *architecturally*: evidence kind (observed vs. inferred) is separate from confidence; a correlation key ties evidence streams together without requiring all to exist; and `Evaluate` is a pure, I/O-free function that never fabricates a verdict from a missing observation.

`internal/wafval` does **not** import `controlval` and does not modify or generalize it. Three domain reasons make reuse the wrong call rather than merely inconvenient:

1. **`controlval` collapses detection and enforcement.** Its `Outcome` is a single axis (`allowed`/`blocked`/`mfa_challenged`/…). A WAF can detect-and-log a malicious request while allowing it through, or block a request and log that decision — detection and enforcement are independent dimensions that `controlval` has no way to represent.
2. **`controlval` has no collection-coverage concept.** Its `Observe` returns an `Outcome=unknown` observation for an uncorrelated attempt, but it cannot distinguish "searched a reachable source and found nothing" from "the source was unavailable." That distinction is load-bearing for every defensible negative WAF finding.
3. **`controlval`'s verdict is the generic PASS/FAIL/ERROR/SKIPPED taxonomy.** WAF findings need an attack-oriented taxonomy (blocked / detected-but-allowed / missed / incorrectly-blocked) whose named states carry distinct remediation meaning for a client.

Premature generalization into a shared core is explicitly rejected for Phase 1: extracting a common evidence-correlation core should happen *after* a second concrete vertical makes the shared shape visible, not before. `wafval` follows `controlval`'s conventions as a sibling, the same way `adefficacy` sits beside `controlval`.

## 4. The Three Orthogonal Observation Axes

A single `Observation` is one mechanism's report about one request. Its outcome is **not** one enum; it is three independent axes, because detection, enforcement, and what actually reached the origin are three different facts that can each be known, unknown, or in conflict independently of the others.

```go
package wafval

// Mechanism is the evidence source that produced an observation. It is the
// independence tag: two observations that share a Mechanism are never treated
// as independent corroboration of each other.
type Mechanism string

const (
	MechanismWAFEngine         Mechanism = "waf_engine"         // the WAF's own event/log
	MechanismOriginApp         Mechanism = "origin_app"         // the protected application / origin
	MechanismIndependentSensor Mechanism = "independent_sensor" // a separate observer (e.g. packet capture)
)

// EnforcementAction is what the WAF (or origin) did about the request.
type EnforcementAction string

const (
	EnforcementBlocked    EnforcementAction = "blocked"
	EnforcementAllowed    EnforcementAction = "allowed"
	EnforcementChallenged EnforcementAction = "challenged"
	EnforcementTerminated EnforcementAction = "terminated"
	EnforcementUnknown    EnforcementAction = "unknown"
)

// DetectionOutcome is whether the WAF recognized the request as matching a
// rule/signature, independent of whether it enforced anything.
type DetectionOutcome string

const (
	DetectionMatched    DetectionOutcome = "matched"
	DetectionNotMatched DetectionOutcome = "not_matched" // assertable ONLY with verified-complete coverage
	DetectionUnknown    DetectionOutcome = "unknown"
)

// OriginObservation is whether the protected application actually received /
// processed the request. "not_observed" must never be read as "did not happen".
type OriginObservation string

const (
	OriginReceived    OriginObservation = "received"
	OriginNotObserved OriginObservation = "not_observed"
	OriginUnknown     OriginObservation = "unknown"
)

// EvidenceKind separates a directly observed signal from an inferred one.
type EvidenceKind string

const (
	EvidenceObserved EvidenceKind = "observed"
	EvidenceInferred EvidenceKind = "inferred"
)

// Observation is one mechanism's raw report about one request. Its EventID and
// ObservedAt are preserved verbatim; observations are never merged away.
type Observation struct {
	Mechanism    Mechanism
	Provider     string            // adapter name, e.g. "lab-modsecurity"
	EventID      string            // the mechanism's own event identity
	RequestID    string            // correlation token carried on the HTTP request
	ObservedAt   time.Time
	Enforcement  EnforcementAction
	Detection    DetectionOutcome
	Origin       OriginObservation
	MatchedRule  string            // populated only for MechanismWAFEngine when a rule fired
	EvidenceKind EvidenceKind
	Detail       string
}
```

## 5. Collection Coverage — Absence Requires a Verified Search

A mechanism that produces no matching event tells us nothing until we know whether we actually searched a reachable source. Coverage is therefore a first-class, per-mechanism input, carried alongside the raw observations that search returned.

```go
// Coverage records what a search of one mechanism actually established. A
// negative detection (DetectionNotMatched) is only assertable under
// CoverageSearchedVerifiedNone.
type Coverage string

const (
	CoverageFound                Coverage = "found"                  // a matching event was returned
	CoverageSearchedVerifiedNone Coverage = "searched_verified_none" // search completed, source reachable, no match
	CoverageSearchIncomplete     Coverage = "search_incomplete"      // search ran but coverage not verified
	CoverageSourceUnavailable    Coverage = "source_unavailable"     // the source could not be queried
)

// CollectionResult is one mechanism's search result for one correlation key:
// its coverage plus every raw observation the search returned (possibly several
// for a single request).
type CollectionResult struct {
	Mechanism    Mechanism
	Coverage     Coverage
	Observations []Observation
}
```

`CoverageSearchIncomplete` and `CoverageSourceUnavailable` can never establish a negative; they force evidence completeness down and can only ever yield `Inconclusive` for a claim that depends on that mechanism's negative.

## 6. Correlation, Duplicates, and Ambiguity

`Correlate` merges a set of `CollectionResult`s for one correlation key into a per-axis resolved view. It never discards raw observations.

- **Duplicates** (fix C): two observations from the same mechanism with the **same `EventID`** are the same event seen twice; they dedupe to one and are **not** counted as independent corroboration.
- **Same-mechanism disagreement**: two observations from the same mechanism with **different `EventID`s** that disagree on an axis are a genuine multi-stage/ambiguous report. They are **not** silently collapsed to a single pick; the axis resolves to an explicit `Ambiguous` state and the raw observations are preserved on the result.
- **Cross-mechanism disagreement**: when two **different** mechanisms disagree on an axis (e.g. `waf_engine` reports `blocked` while `origin_app` reports `received`), that axis resolves to `Contradictory`.

```go
// AxisState is the resolved state of one axis after correlation across all
// mechanisms for one key. Agree carries the agreed value; the others do not.
type AxisResolution struct {
	State AxisState // Agree | Contradictory | Ambiguous | Unknown
	// Agreed values are only meaningful when State == AxisAgree.
	Enforcement EnforcementAction
	Detection   DetectionOutcome
	Origin      OriginObservation
}

type CorrelatedView struct {
	Key           CorrelationKey
	EnforcementAx AxisResolution
	DetectionAx   AxisResolution
	OriginAx      AxisResolution
	Raw           []Observation // every observation that fed this view, preserved
}
```

```go
// CorrelationKey ties a test execution to the raw events without presupposing
// the internal execution id is known to the log source. RequestID is the token
// carried on the HTTP request itself.
type CorrelationKey struct {
	TestExecutionID string
	RequestID       string
	Target          string
	Window          TimeWindow
}

type TimeWindow struct {
	Start time.Time
	End   time.Time
}
```

## 7. The Three Independent Result Dimensions

Correlation feeds three dimensions that are computed separately and never collapsed into one status. **Evidence completeness describes coverage, not truth.** A complete evidence set must not automatically imply high confidence.

```go
type EvidenceCompleteness string

const (
	CompletenessComplete     EvidenceCompleteness = "complete"
	CompletenessPartial      EvidenceCompleteness = "partial"
	CompletenessInsufficient EvidenceCompleteness = "insufficient"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)
```

- **`EvidenceCompleteness`** is derived purely from `Coverage`, and each claim distinguishes two tiers of mechanism: a **minimum** mechanism (without which no verdict can be rendered) and **corroborating** mechanism(s) (independent sources that, when present, let the finding reach `Complete`). `Complete` = minimum present *and* every corroborating mechanism present with usable coverage; `Partial` = minimum present but some corroborating mechanism absent/unavailable; `Insufficient` = the minimum itself absent. "Present with usable coverage" means `found` or `searched_verified_none`; `search_incomplete`/`source_unavailable` do not count as present.
- **`Confidence`** takes a **ceiling** from completeness (`Complete`→candidate `High`, `Partial`→candidate `Medium`, `Insufficient`→`None`) and is then only ever **downgraded**: any `Contradictory` axis forces `None`; an `EvidenceInferred`-only required observation caps at `Medium`. Confidence is never upgraded above its completeness ceiling. This is the structural guarantee that "complete" does not imply "confident."
- The resolved **axes** (§6) are the third dimension — what was observed, per axis, including explicit `Contradictory`/`Ambiguous`.

## 8. Claim Types and Evidence-Sufficiency Rules

A claim is the question being asked of the evidence. Each claim type declares precisely which mechanisms it requires and how its axes map to a verdict. There is no universal rule.

| ClaimType | Minimum mechanism | Corroborating (needed for `Complete`/`High`) | Negative (`not_matched`) assertable when |
|---|---|---|---|
| `Prevention` (malicious request should be blocked) | `waf_engine` | `origin_app` | WAF-engine coverage is `searched_verified_none` (per §5) |
| `FalsePositive` (legitimate request should stay allowed) | `waf_engine` | — | not used — asks only about enforcement being allowed |
| `PolicyGap` (weakened policy should let through what baseline blocks) | evaluated as a **pair** of two `Prevention`-shaped legs | per-leg, as `Prevention` | per-leg, as `Prevention`; plus the pair rule (§10) |

```go
type ClaimType string

const (
	ClaimPrevention    ClaimType = "prevention"
	ClaimFalsePositive ClaimType = "false_positive"
	ClaimPolicyGap     ClaimType = "policy_gap"
)

// Expectation declares what a claim expects and the policy basis it derives
// from. PolicyVerified is false whenever the policy was merely supplied as test
// input (never confirmed in force).
type Expectation struct {
	Claim         ClaimType
	PolicyBasis   string
	PolicyVerified bool
}
```

## 9. Verdict Taxonomy and Deterministic Derivation

Seven terminal verdicts. Six are `waf.txt`'s attack-oriented taxonomy; `Allowed` is the added legitimate-success state. `NotTested` is **not** an evidence-derived verdict — it is a catalog/execution status assigned above the evaluator, before any execution attempt exists, and the evaluator is never invoked for it.

```go
type Verdict string

const (
	VerdictBlocked            Verdict = "blocked"
	VerdictDetectedButAllowed Verdict = "detected_but_allowed"
	VerdictMissed             Verdict = "missed"
	VerdictIncorrectlyBlocked Verdict = "incorrectly_blocked"
	VerdictAllowed            Verdict = "allowed"      // legitimate request correctly permitted
	VerdictInconclusive       Verdict = "inconclusive"
	// NotTested is intentionally NOT here; it is a catalog status.
)
```

**Which claim may produce which verdict** (enforced by `Valid`):

| Verdict | Producible by |
|---|---|
| `Blocked` | `Prevention`, `PolicyGap` |
| `DetectedButAllowed` | `Prevention`, `PolicyGap` |
| `Missed` | `Prevention`, `PolicyGap` |
| `IncorrectlyBlocked` | `FalsePositive` |
| `Allowed` | `FalsePositive` **only** |
| `Inconclusive` | any claim |

The verdict is a pure, deterministic function of `(ClaimType, CorrelatedView, EvidenceCompleteness, Confidence)`. Two guards run first, before any claim-specific logic:

1. Any axis the claim depends on resolving to `Contradictory` → `Inconclusive` (complete-but-disagreeing must never read as confident).
2. `EvidenceCompleteness == Insufficient` → `Inconclusive`.

Then per claim:

**`Prevention`** (enforcement axis drives it; `allowed` can never become `Allowed`):
```
enforcement blocked                          -> Blocked
enforcement allowed & detection matched      -> DetectedButAllowed
enforcement allowed & detection not_matched  -> Missed       (requires searched_verified_none coverage)
enforcement allowed & detection unknown      -> Inconclusive
```

**`FalsePositive`** (a legitimate request):
```
enforcement allowed                          -> Allowed
enforcement blocked | challenged | terminated-> IncorrectlyBlocked
enforcement unknown                          -> Inconclusive
```

**`PolicyGap`** (§10) resolves each leg as a `Prevention` result first, then applies the pair rule.

This is what makes "attack allowed" and "legitimate request allowed" structurally incapable of sharing a verdict: the same `enforcement=allowed` resolves to `Missed`/`DetectedButAllowed` under `Prevention` and to `Allowed` only under `FalsePositive`. The claim type decides, never the raw enforcement action.

```go
// Valid rejects a verdict/claim/completeness combination that violates the
// taxonomy's invariants. A well-typed Go value can still be an invalid state;
// this is the single place that catches it. E.g. VerdictAllowed with any claim
// other than FalsePositive, or any non-Inconclusive verdict with
// CompletenessInsufficient, is rejected.
func Valid(claim ClaimType, v Verdict, c EvidenceCompleteness) error
```

## 10. PolicyGap Pair Evaluation

PolicyGap must not collapse into a bare failed-prevention report. It compares a **baseline** leg (policy as-shipped, expected to block) against a **weakened** leg (an exclusion/detection-only change, expected to reveal a gap), and its verdict depends on *both* legs' observed behavior, the evidence quality of each, **and** explicit confirmation that the policy difference was actually in force.

```go
type Pair struct {
	Baseline Result // a ClaimPrevention result for the as-shipped policy
	Weakened Result // a ClaimPrevention result for the weakened policy
	// PolicyDifferentiationConfirmed is adapter-supplied evidence that the
	// weakened policy was actually in force for the weakened leg. Without it,
	// a difference in responses is not attributable to the policy change.
	PolicyDifferentiationConfirmed bool
}
```

Derivation (first matching row wins; every verdict carries a Reason naming the attribution):
```
PolicyDifferentiationConfirmed == false            -> Inconclusive ("policy change not confirmed in force")
baseline not a trustworthy Blocked                 -> Inconclusive ("baseline did not establish a reliable block")
baseline Blocked & weakened Missed                 -> Missed             ("enforcement AND detection gap, attributable to policy weakening")
baseline Blocked & weakened DetectedButAllowed     -> DetectedButAllowed ("enforcement weakness; detection still fired")
baseline Blocked & weakened Blocked                -> Blocked            ("no gap demonstrated under this weakening")
```
"Trustworthy Blocked" means the baseline leg's own verdict is `Blocked` at `Confidence >= Medium`; a baseline that is itself `Inconclusive` or low-confidence cannot anchor an attribution.

## 11. Result Type and `NotTested`

```go
// Result is one claim's graded outcome. It preserves the raw observations and
// the three independent dimensions; Verdict is the derived summary, never set
// directly by an adapter.
type Result struct {
	Key          CorrelationKey
	Expectation  Expectation
	View         CorrelatedView
	Completeness EvidenceCompleteness
	Confidence   Confidence
	Verdict      Verdict
	Reason       string
}
```

`NotTested` vs `Inconclusive` (explicit, per brainstorming): `NotTested` is a catalog/execution status assigned *before* the evaluator runs — no execution attempt was ever recorded, so there is no `Result`. The instant an execution attempt is recorded — even one that yields zero usable observations — `EvaluateClaim` runs and the worst verdict it can return is `Inconclusive`. The evaluator never returns `NotTested`, and `NotTested` never appears as a `Verdict` value.

## 12. Vendor-Neutral Domain vs. Lab-Adapter Responsibility

**`internal/wafval` (pure domain, no I/O, stdlib + `time` only):** the axes and their values; `Coverage`, `CollectionResult`; `CorrelationKey`, `CorrelatedView`, `Correlate` (dedup by `EventID`, ambiguity and contradiction flagging); `ClaimType`, `Expectation`; `EvidenceCompleteness`, `Confidence`; `Verdict`, `EvaluateClaim` + per-claim derivation; `Pair`, `EvaluatePolicyGap`; `Valid`. No HTTP, no ModSecurity, no engine names, no execution orchestration.

**Lab adapter package (sibling, Phase 1, lab-gated — not designed in detail in this spec):** drives bounded, authorized HTTP requests (each stamped with a `RequestID`) at a controlled application behind ModSecurity/OWASP CRS; reads the WAF audit log and the origin application's own log; reports each search's `Coverage` honestly; adapts raw log entries into `[]Observation` and `CollectionResult`. It owns the collection seam, mirroring how `adefficacy` owns `ControlDecisionSource` rather than reusing a generic `Provider.Observe`. The seam's exact signature and the controlled-app/ModSecurity wiring are a lab-gated follow-on (consistent with `adefficacy`/`controlval` shipping fake-backed only until a lab run is authorized); this spec fixes only the vendor-neutral contract the adapter must satisfy.

## 13. Acceptance Gate

The gate is the set of tests that prove the evidence and verdict rules. All are fixture-driven and require no live WAF.

Original eight:
1. `Prevention` + known malicious request, WAF+origin agree blocked → `Blocked`, `High`.
2. `FalsePositive` + legitimate request allowed → `Allowed`.
3. `PolicyGap`, baseline Blocked, weakened allowed+not_matched, differentiation confirmed → `Missed` with policy-attribution Reason (reads as a gap, not a bare failed-prevention test).
4. `PolicyGap`, untrustworthy baseline → `Inconclusive`.
5. `Prevention`, WAF-only evidence, origin telemetry unavailable → reaches `Blocked` but `Confidence` capped below `High` (partial completeness).
6. `Prevention`, both mechanisms collected (Complete) but contradict → `Confidence=None`, `Verdict=Inconclusive` (completeness ≠ confidence).
7. `NotTested` (no execution attempt, no `Result`) is distinct from `Inconclusive` (attempt recorded, zero usable observations).
8. `Valid` rejects invalid verdict/completeness pairs (e.g. `Blocked` + `Insufficient`).

Six added from spec review:
9. Detection and enforcement vary independently: `matched`+`allowed` yields a distinct result from `not_matched`+`allowed` (`DetectedButAllowed` vs `Missed`).
10. `CoverageSearchIncomplete` and `CoverageSourceUnavailable` can never yield `Missed` — only `Inconclusive`.
11. Two same-mechanism observations with identical `EventID` dedupe to one and are not counted as independent corroboration (a single-mechanism "agreement" never reaches cross-mechanism `High`).
12. Two same-mechanism observations with different `EventID`s that disagree surface an `Ambiguous` axis, not a silent pick; raw observations preserved.
13. `PolicyGap` with `PolicyDifferentiationConfirmed=false` → `Inconclusive` even when the two legs' responses differ.
14. `Prevention` with `enforcement=allowed` never returns `Allowed` (returns `Missed` or `DetectedButAllowed`); `Allowed` is reachable only via `FalsePositive`.

## 14. Explicitly Deferred

- Any commercial WAF vendor adapter (AWS WAF, Cloudflare, F5, Imperva, Akamai).
- Any customer-targeted execution; the authorization/bounded-execution/deployment-safety readiness gate that must precede it.
- The lab adapter's concrete collection-seam signature and ModSecurity/controlled-app wiring (lab-gated follow-on).
- The full attack-payload library (Phase 2) and all later roadmap phases.
- Extraction of a shared evidence-correlation core between `controlval` and `wafval` (revisit only after a second vertical makes the shared shape concrete).
