# WAF BAS Mastery Phase 1 (wafval) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafval`, the vendor-neutral WAF evidence-and-verdict domain package, with a fixture-driven acceptance gate proving the evidence and verdict rules.

**Architecture:** A pure (I/O-free, stdlib + `time` only) Go package that models WAF evidence as three orthogonal observation axes plus first-class collection coverage, correlates raw observations into a per-axis resolved view (dedup/ambiguity/contradiction aware), computes three independent result dimensions (completeness, confidence, resolved axes), and derives one of seven terminal verdicts deterministically per claim type. Follows the architectural patterns of `internal/controlval` + `internal/adefficacy` without importing them. The lab adapter (HTTP/ModSecurity/log collection) is a deferred follow-on; this plan builds the domain package only.

**Tech Stack:** Go (module `github.com/audspect/bas`, `orchestrator/` dir), standard library + `time` only. Tests are pure unit tests — `go test ./internal/wafval/...`, no DB, no testcontainers.

**Spec:** `docs/superpowers/specs/2026-10-15-waf-bas-phase1-wafval-design.md`

## Global Constraints

- Package `internal/wafval` imports **stdlib + `time` only**. It MUST NOT import `internal/controlval`, `internal/adefficacy`, any AD type, or any WAF-vendor type. (spec §3, §12)
- No I/O anywhere in the package: no HTTP, no DB, no file access, no clock reads inside evaluation. Evaluation functions are pure over their inputs. (spec §12)
- `NotTested` is a catalog/execution status, **never** a `Verdict` value and never returned by the evaluator. (spec §9, §11)
- "Complete evidence" must never automatically imply "high confidence" — confidence is capped by completeness and only ever downgraded. (spec §7)
- Absence of a matching event is meaningful only under verified coverage: `DetectionNotMatched` is assertable **only** when the WAF-engine mechanism's `Coverage == CoverageSearchedVerifiedNone`. (spec §5, §8)
- Raw observations, their `EventID`s and `ObservedAt` timestamps, are preserved through correlation — never discarded or merged away. (spec §4, §6)
- `VerdictAllowed` is reachable **only** via a `ClaimFalsePositive` claim. (spec §9)
- Files stay small and single-responsibility, matching `controlval`/`adefficacy` sizing (~230-line core, focused files). (repo convention)

## Review Focus

These are the input classes the spec implies but that are easy to leave uncovered; each has a dedicated test in the owning task.

- **Empty evidence set** (a recorded attempt with zero `CollectionResult`s) must yield `Inconclusive`, not a panic and not `NotTested` — Task 5 (`TestEvaluateClaim_NoObservations_Inconclusive`).
- **`search_incomplete`/`source_unavailable` coverage** must never let a negative detection stand; it can only produce `Inconclusive` for a claim depending on that negative — Task 5 (`TestEvaluateClaim_IncompleteCoverage_CannotEstablishMissed`).
- **Same-mechanism duplicate `EventID`** must dedupe and must not be counted as independent corroboration (so WAF-engine-alone can never reach `High`) — Task 4 (`TestCorrelate_DuplicateEventID_NotIndependentCorroboration`).
- **Same-mechanism distinct-`EventID` disagreement** must surface `AxisAmbiguous`, not silently pick one — Task 4 (`TestCorrelate_SameMechanismDisagreement_Ambiguous`).
- **`PolicyGap` with `PolicyDifferentiationConfirmed=false`** must be `Inconclusive` even when the two legs' responses differ — Task 6 (`TestEvaluatePolicyGap_UnconfirmedDifferentiation_Inconclusive`).
- **`Prevention` with `enforcement=allowed`** must never return `VerdictAllowed` (returns `Missed`/`DetectedButAllowed`); the claim type, not the raw action, decides — Task 5 (`TestEvaluateClaim_PreventionAllowed_NeverVerdictAllowed`).

---

## File Structure

- `internal/wafval/wafval.go` — all domain value types and the `Valid` invariant checker. No logic beyond `Valid` and tiny predicate helpers.
- `internal/wafval/correlate.go` — `AxisState`, `AxisResolution`, `CorrelatedView`, and `Correlate`.
- `internal/wafval/evaluate.go` — `EvaluateClaim`, the completeness/confidence derivation, and per-claim `deriveVerdict`.
- `internal/wafval/policygap.go` — `Pair` and `EvaluatePolicyGap`.
- `internal/wafval/wafval_test.go`, `correlate_test.go`, `evaluate_test.go`, `policygap_test.go` — tests per file.
- `internal/wafval/support_test.go` — shared fixture builders.

---

## Task 1: Domain value types

**Files:**
- Create: `internal/wafval/wafval.go`
- Test: `internal/wafval/wafval_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: all types below, consumed by every later task.
  - `Mechanism` (`MechanismWAFEngine`, `MechanismOriginApp`, `MechanismIndependentSensor`)
  - `EnforcementAction` (`EnforcementBlocked`, `EnforcementAllowed`, `EnforcementChallenged`, `EnforcementTerminated`, `EnforcementUnknown`)
  - `DetectionOutcome` (`DetectionMatched`, `DetectionNotMatched`, `DetectionUnknown`)
  - `OriginObservation` (`OriginReceived`, `OriginNotObserved`, `OriginUnknown`)
  - `EvidenceKind` (`EvidenceObserved`, `EvidenceInferred`)
  - `Coverage` (`CoverageFound`, `CoverageSearchedVerifiedNone`, `CoverageSearchIncomplete`, `CoverageSourceUnavailable`)
  - `EvidenceCompleteness` (`CompletenessComplete`, `CompletenessPartial`, `CompletenessInsufficient`)
  - `Confidence` (`ConfidenceHigh`, `ConfidenceMedium`, `ConfidenceLow`, `ConfidenceNone`)
  - `ClaimType` (`ClaimPrevention`, `ClaimFalsePositive`, `ClaimPolicyGap`)
  - `Verdict` (`VerdictBlocked`, `VerdictDetectedButAllowed`, `VerdictMissed`, `VerdictIncorrectlyBlocked`, `VerdictAllowed`, `VerdictInconclusive`)
  - `TimeWindow{Start, End time.Time}`
  - `CorrelationKey{TestExecutionID, RequestID, Target string; Window TimeWindow}`
  - `Observation{Mechanism; Provider, EventID, RequestID string; ObservedAt time.Time; Enforcement EnforcementAction; Detection DetectionOutcome; Origin OriginObservation; MatchedRule string; EvidenceKind EvidenceKind; Detail string}`
  - `CollectionResult{Mechanism Mechanism; Coverage Coverage; Observations []Observation}`
  - `Expectation{Claim ClaimType; PolicyBasis string; PolicyVerified bool}`
  - `func (c Coverage) Present() bool` — true for `CoverageFound` and `CoverageSearchedVerifiedNone` only.
  - `func Valid(claim ClaimType, v Verdict, c EvidenceCompleteness) error`

- [ ] **Step 1: Write the failing test for `Coverage.Present`**

```go
package wafval

import "testing"

func TestCoverage_Present(t *testing.T) {
	cases := map[Coverage]bool{
		CoverageFound:                true,
		CoverageSearchedVerifiedNone: true,
		CoverageSearchIncomplete:     false,
		CoverageSourceUnavailable:    false,
	}
	for cov, want := range cases {
		if got := cov.Present(); got != want {
			t.Errorf("Coverage(%q).Present() = %v, want %v", cov, got, want)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/wafval/... -run TestCoverage_Present`
Expected: FAIL — build error, `wafval` package / `Present` undefined.

- [ ] **Step 3: Write the types and `Present`**

Create `internal/wafval/wafval.go` with the package doc comment, all the `const`/`type` declarations listed in Produces, and:

```go
// Present reports whether a search of this mechanism actually established
// coverage. search_incomplete and source_unavailable do not count as present
// and can never establish a negative finding.
func (c Coverage) Present() bool {
	return c == CoverageFound || c == CoverageSearchedVerifiedNone
}
```

Package doc comment (top of file):

```go
// Package wafval is a vendor-neutral, I/O-free model for grading what a WAF
// did about a controlled test request. It models evidence as three orthogonal
// axes (enforcement, detection, origin) plus first-class collection coverage,
// correlates raw observations into a per-axis resolved view, and derives one
// of seven terminal verdicts deterministically per claim type. It imports
// stdlib + time only and does NOT depend on internal/controlval, any AD type,
// or any WAF-vendor type. The lab adapter that produces observations is a
// separate, deferred package.
package wafval
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/wafval/... -run TestCoverage_Present`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `Valid`**

```go
func TestValid(t *testing.T) {
	// VerdictAllowed only from FalsePositive.
	if err := Valid(ClaimPrevention, VerdictAllowed, CompletenessComplete); err == nil {
		t.Error("Prevention+Allowed should be rejected")
	}
	if err := Valid(ClaimFalsePositive, VerdictAllowed, CompletenessComplete); err != nil {
		t.Errorf("FalsePositive+Allowed should be valid, got %v", err)
	}
	// IncorrectlyBlocked only from FalsePositive.
	if err := Valid(ClaimPrevention, VerdictIncorrectlyBlocked, CompletenessComplete); err == nil {
		t.Error("Prevention+IncorrectlyBlocked should be rejected")
	}
	// Non-Inconclusive verdict with Insufficient completeness is rejected.
	if err := Valid(ClaimPrevention, VerdictBlocked, CompletenessInsufficient); err == nil {
		t.Error("Blocked+Insufficient should be rejected")
	}
	// Inconclusive is valid for any claim and any completeness.
	if err := Valid(ClaimPrevention, VerdictInconclusive, CompletenessInsufficient); err != nil {
		t.Errorf("Inconclusive+Insufficient should be valid, got %v", err)
	}
	// Blocked is valid for Prevention at Complete.
	if err := Valid(ClaimPrevention, VerdictBlocked, CompletenessComplete); err != nil {
		t.Errorf("Prevention+Blocked+Complete should be valid, got %v", err)
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `go test ./internal/wafval/... -run TestValid`
Expected: FAIL — `Valid` undefined.

- [ ] **Step 7: Implement `Valid`**

```go
// Valid rejects a verdict/claim/completeness combination that violates the
// taxonomy's invariants. A well-typed value can still be an invalid state;
// this is the single place that catches it.
func Valid(claim ClaimType, v Verdict, c EvidenceCompleteness) error {
	// Inconclusive is always valid.
	if v == VerdictInconclusive {
		return nil
	}
	// Any non-Inconclusive verdict requires more than insufficient evidence.
	if c == CompletenessInsufficient {
		return fmt.Errorf("verdict %q requires evidence beyond insufficient", v)
	}
	allowed := map[ClaimType]map[Verdict]bool{
		ClaimPrevention: {
			VerdictBlocked: true, VerdictDetectedButAllowed: true, VerdictMissed: true,
		},
		ClaimFalsePositive: {
			VerdictAllowed: true, VerdictIncorrectlyBlocked: true,
		},
		ClaimPolicyGap: {
			VerdictBlocked: true, VerdictDetectedButAllowed: true, VerdictMissed: true,
		},
	}
	if byClaim, ok := allowed[claim]; ok && byClaim[v] {
		return nil
	}
	return fmt.Errorf("verdict %q is not producible by claim %q", v, claim)
}
```

Add `import "fmt"` to the file's import block (alongside `time`).

- [ ] **Step 8: Run it to verify it passes**

Run: `go test ./internal/wafval/... -run TestValid`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/wafval/wafval.go internal/wafval/wafval_test.go
git commit -m "feat(wafval): domain value types, Coverage.Present, Valid invariant

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Shared test fixtures

**Files:**
- Create: `internal/wafval/support_test.go`

**Interfaces:**
- Consumes: Task 1 types.
- Produces: fixture builders used by Tasks 4-6 tests.
  - `func wafEngineObs(enf EnforcementAction, det DetectionOutcome, opts ...obsOpt) Observation`
  - `func originObs(origin OriginObservation, opts ...obsOpt) Observation`
  - `type obsOpt func(*Observation)`
  - `func withEventID(id string) obsOpt`
  - `func withEvidenceKind(k EvidenceKind) obsOpt`
  - `func collResult(m Mechanism, cov Coverage, obs ...Observation) CollectionResult`
  - `func testKey() CorrelationKey`

This task has no behavior of its own; it is validated by compiling under Task 4's first test. There is no standalone test run or commit — fold its file into Task 4's first commit. (It is listed as a separate task only to document the fixtures' signatures for later tasks; an implementer may create the file at the start of Task 4.)

- [ ] **Step 1: Create the fixtures file**

```go
package wafval

import "time"

type obsOpt func(*Observation)

func withEventID(id string) obsOpt     { return func(o *Observation) { o.EventID = id } }
func withEvidenceKind(k EvidenceKind) obsOpt { return func(o *Observation) { o.EvidenceKind = k } }

func testKey() CorrelationKey {
	return CorrelationKey{
		TestExecutionID: "exec-1",
		RequestID:       "req-1",
		Target:          "https://app.lab/login",
		Window:          TimeWindow{Start: time.Unix(0, 0), End: time.Unix(60, 0)},
	}
}

func wafEngineObs(enf EnforcementAction, det DetectionOutcome, opts ...obsOpt) Observation {
	o := Observation{
		Mechanism:    MechanismWAFEngine,
		Provider:     "lab-modsecurity",
		EventID:      "waf-evt",
		RequestID:    "req-1",
		ObservedAt:   time.Unix(1, 0),
		Enforcement:  enf,
		Detection:    det,
		Origin:       OriginUnknown,
		EvidenceKind: EvidenceObserved,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func originObs(origin OriginObservation, opts ...obsOpt) Observation {
	o := Observation{
		Mechanism:    MechanismOriginApp,
		Provider:     "lab-origin",
		EventID:      "origin-evt",
		RequestID:    "req-1",
		ObservedAt:   time.Unix(2, 0),
		Enforcement:  EnforcementUnknown,
		Detection:    DetectionUnknown,
		Origin:       origin,
		EvidenceKind: EvidenceObserved,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func collResult(m Mechanism, cov Coverage, obs ...Observation) CollectionResult {
	return CollectionResult{Mechanism: m, Coverage: cov, Observations: obs}
}
```

(No test run; this file compiles as part of Task 4.)

---

## Task 3: Correlation types

**Files:**
- Create: `internal/wafval/correlate.go` (types only; `Correlate` body added in Task 4)
- Test: `internal/wafval/correlate_test.go` (created in Task 4)

**Interfaces:**
- Consumes: Task 1 types.
- Produces:
  - `AxisState` (`AxisAgree`, `AxisContradictory`, `AxisAmbiguous`, `AxisUnknown`)
  - `AxisResolution{State AxisState; Enforcement EnforcementAction; Detection DetectionOutcome; Origin OriginObservation}`
  - `CorrelatedView{Key CorrelationKey; EnforcementAx, DetectionAx, OriginAx AxisResolution; Raw []Observation}`

Task 3 is the type declarations only; it has no standalone test and is folded into Task 4's commit. It is split out so Task 4's `Correlate` signature is unambiguous.

- [ ] **Step 1: Create `correlate.go` with the types**

```go
package wafval

// AxisState is the resolved state of one evidence axis after correlation
// across all mechanisms for one key.
type AxisState string

const (
	AxisAgree         AxisState = "agree"         // all contributing mechanisms agree; value carried
	AxisContradictory AxisState = "contradictory" // two DIFFERENT mechanisms disagree
	AxisAmbiguous     AxisState = "ambiguous"     // same mechanism, distinct events, disagree
	AxisUnknown       AxisState = "unknown"       // no contributing mechanism had a known value
)

// AxisResolution is one axis's resolved state. The value fields are meaningful
// only when State == AxisAgree.
type AxisResolution struct {
	State       AxisState
	Enforcement EnforcementAction
	Detection   DetectionOutcome
	Origin      OriginObservation
}

// CorrelatedView is the per-axis resolved view for one key. Raw preserves every
// observation that fed the view, never discarded.
type CorrelatedView struct {
	Key           CorrelationKey
	EnforcementAx AxisResolution
	DetectionAx   AxisResolution
	OriginAx      AxisResolution
	Raw           []Observation
}
```

(No test run; committed with Task 4.)

---

## Task 4: `Correlate` — dedup, ambiguity, contradiction

**Files:**
- Modify: `internal/wafval/correlate.go` (add `Correlate` and axis helpers)
- Create: `internal/wafval/correlate_test.go`
- Create: `internal/wafval/support_test.go` (Task 2), `internal/wafval/correlate.go` types (Task 3) if not yet present

**Interfaces:**
- Consumes: Task 1 types, Task 2 fixtures, Task 3 types.
- Produces:
  - `func Correlate(key CorrelationKey, results []CollectionResult) CorrelatedView`

Correlation rules (spec §6):
1. Flatten all observations across results into `Raw` (preserved verbatim, in input order).
2. Dedup: within one mechanism, observations sharing an `EventID` collapse to one (first wins); duplicates are not independent.
3. For each axis, gather the distinct *known* values each mechanism reports (ignoring that axis's `*Unknown` value):
   - If no mechanism reports a known value → `AxisUnknown`.
   - If a single mechanism reports two distinct known values from distinct `EventID`s → `AxisAmbiguous`.
   - If two different mechanisms report different known values → `AxisContradictory`.
   - Otherwise (all known values equal) → `AxisAgree` with that value.
4. A mechanism whose own events are ambiguous on an axis contributes "ambiguous", which makes the axis `AxisAmbiguous` unless another mechanism already makes it `AxisContradictory` (contradiction across mechanisms outranks within-mechanism ambiguity).

- [ ] **Step 1: Write the failing test — cross-mechanism agreement**

```go
package wafval

import "testing"

func TestCorrelate_CrossMechanismAgreement(t *testing.T) {
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
		collResult(MechanismOriginApp, CoverageSearchedVerifiedNone, originObs(OriginNotObserved)),
	})
	if v.EnforcementAx.State != AxisAgree || v.EnforcementAx.Enforcement != EnforcementBlocked {
		t.Errorf("enforcement = %+v, want Agree/blocked", v.EnforcementAx)
	}
	if v.DetectionAx.State != AxisAgree || v.DetectionAx.Detection != DetectionMatched {
		t.Errorf("detection = %+v, want Agree/matched", v.DetectionAx)
	}
	if len(v.Raw) != 2 {
		t.Errorf("Raw len = %d, want 2 (observations preserved)", len(v.Raw))
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/wafval/... -run TestCorrelate_CrossMechanismAgreement`
Expected: FAIL — `Correlate` undefined.

- [ ] **Step 3: Implement `Correlate` and axis helpers**

Add to `correlate.go`:

```go
// Correlate merges collection results for one key into a per-axis resolved
// view. It never discards raw observations; it dedups same-mechanism events by
// EventID and distinguishes within-mechanism ambiguity from cross-mechanism
// contradiction.
func Correlate(key CorrelationKey, results []CollectionResult) CorrelatedView {
	var raw []Observation
	for _, r := range results {
		raw = append(raw, r.Observations...)
	}
	view := CorrelatedView{Key: key, Raw: raw}
	view.EnforcementAx = resolveEnforcement(results)
	view.DetectionAx = resolveDetection(results)
	view.OriginAx = resolveOrigin(results)
	return view
}

// axisAgg holds, per mechanism, the distinct known values seen on one axis
// (already deduped by EventID within each mechanism).
type axisAgg struct {
	perMech map[Mechanism]map[string]bool // mechanism -> set of distinct known values
}

// collect builds an axisAgg for one axis. valueOf returns ("", false) for the
// axis's unknown value, else (value, true). Same-mechanism events sharing an
// EventID are deduped so a duplicate is never independent corroboration.
func collect(results []CollectionResult, valueOf func(Observation) (string, bool)) axisAgg {
	agg := axisAgg{perMech: map[Mechanism]map[string]bool{}}
	for _, r := range results {
		seenEvent := map[string]bool{}
		for _, o := range r.Observations {
			if seenEvent[o.EventID] {
				continue // dedup: same mechanism, same event -> counted once
			}
			seenEvent[o.EventID] = true
			val, known := valueOf(o)
			if !known {
				continue
			}
			if agg.perMech[o.Mechanism] == nil {
				agg.perMech[o.Mechanism] = map[string]bool{}
			}
			agg.perMech[o.Mechanism][val] = true
		}
	}
	return agg
}

// resolveState turns an axisAgg into an AxisState + the agreed value string.
// Cross-mechanism contradiction outranks within-mechanism ambiguity.
func resolveState(agg axisAgg) (AxisState, string) {
	allValues := map[string]bool{}
	for _, vals := range agg.perMech {
		for v := range vals {
			allValues[v] = true
		}
	}
	mechCount := len(agg.perMech)
	switch {
	case mechCount == 0:
		return AxisUnknown, ""
	case len(allValues) == 1:
		for v := range allValues {
			return AxisAgree, v
		}
		return AxisUnknown, "" // unreachable; len==1 always yields a value
	case mechCount == 1:
		return AxisAmbiguous, "" // one mechanism, multiple distinct values
	default:
		return AxisContradictory, "" // multiple mechanisms disagree
	}
}

func resolveEnforcement(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Enforcement == EnforcementUnknown {
			return "", false
		}
		return string(o.Enforcement), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Enforcement: EnforcementAction(val)}
}

func resolveDetection(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Detection == DetectionUnknown {
			return "", false
		}
		return string(o.Detection), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Detection: DetectionOutcome(val)}
}

func resolveOrigin(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Origin == OriginUnknown {
			return "", false
		}
		return string(o.Origin), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Origin: OriginObservation(val)}
}
```

Also create `internal/wafval/support_test.go` (Task 2 content) and ensure `correlate.go`'s Task 3 types are present.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/wafval/... -run TestCorrelate_CrossMechanismAgreement`
Expected: PASS.

- [ ] **Step 5: Write the failing test — duplicate EventID is not independent corroboration**

```go
func TestCorrelate_DuplicateEventID_NotIndependentCorroboration(t *testing.T) {
	// Same WAF event reported twice (same EventID) must count once.
	o := wafEngineObs(EnforcementBlocked, DetectionMatched, withEventID("dup"))
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, o, o),
	})
	if v.EnforcementAx.State != AxisAgree || v.EnforcementAx.Enforcement != EnforcementBlocked {
		t.Errorf("enforcement = %+v, want Agree/blocked (duplicate collapsed)", v.EnforcementAx)
	}
	// Only one mechanism contributed, so this can never be cross-mechanism.
}
```

- [ ] **Step 6: Run it to verify it fails, then passes**

Run: `go test ./internal/wafval/... -run TestCorrelate_DuplicateEventID_NotIndependentCorroboration`
Expected: PASS (behavior already implemented by dedup). If it FAILS, the dedup logic is wrong — fix `collect`, do not change the test.

Note: this test passes immediately against the Step 3 implementation. That is expected — it is a regression guard for the dedup rule, not a RED-first driver. The RED-first driver for dedup independence is the confidence cap in Task 5 (`TestEvaluateClaim_WAFOnly_CapsAtMedium`), where a single mechanism must not reach `High`.

- [ ] **Step 7: Write the failing test — same-mechanism disagreement is ambiguous**

```go
func TestCorrelate_SameMechanismDisagreement_Ambiguous(t *testing.T) {
	// One WAF mechanism emits two DISTINCT events that disagree on enforcement.
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound,
			wafEngineObs(EnforcementBlocked, DetectionMatched, withEventID("e1")),
			wafEngineObs(EnforcementAllowed, DetectionMatched, withEventID("e2")),
		),
	})
	if v.EnforcementAx.State != AxisAmbiguous {
		t.Errorf("enforcement state = %q, want ambiguous", v.EnforcementAx.State)
	}
	if len(v.Raw) != 2 {
		t.Errorf("Raw len = %d, want 2 (both events preserved)", len(v.Raw))
	}
}
```

- [ ] **Step 8: Run it to verify it fails**

Run: `go test ./internal/wafval/... -run TestCorrelate_SameMechanismDisagreement_Ambiguous`
Expected: FAIL if `resolveState`'s `mechCount == 1` branch is wrong. (Against Step 3 code it should PASS; if it does, keep it as a guard and continue.)

- [ ] **Step 9: Write the failing test — cross-mechanism contradiction**

```go
func TestCorrelate_CrossMechanismContradiction(t *testing.T) {
	// WAF says blocked; origin says it received/processed the request.
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
		collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
	})
	// Enforcement axis: WAF blocked, but origin received implies not blocked.
	// Model origin "received" as an enforcement signal of allowed on the origin
	// mechanism so the contradiction surfaces on the enforcement axis.
	if v.OriginAx.State != AxisAgree || v.OriginAx.Origin != OriginReceived {
		t.Errorf("origin = %+v, want Agree/received", v.OriginAx)
	}
	// Enforcement: only WAF reports enforcement, origin reports origin axis.
	if v.EnforcementAx.State != AxisAgree || v.EnforcementAx.Enforcement != EnforcementBlocked {
		t.Errorf("enforcement = %+v, want Agree/blocked (only WAF reports enforcement)", v.EnforcementAx)
	}
}
```

Note: contradiction between "WAF blocked" and "origin received" is a *cross-axis* inconsistency (enforcement vs origin), resolved at evaluation time (Task 5), not a same-axis contradiction. A same-axis cross-mechanism contradiction requires two mechanisms that both report the *same* axis. The independent sensor is the second enforcement reporter; add that case:

```go
func TestCorrelate_CrossMechanismContradiction_SameAxis(t *testing.T) {
	wafBlocked := wafEngineObs(EnforcementBlocked, DetectionMatched)
	sensorAllowed := Observation{
		Mechanism: MechanismIndependentSensor, Provider: "lab-pcap", EventID: "pcap-1",
		RequestID: "req-1", Enforcement: EnforcementAllowed, Detection: DetectionUnknown, Origin: OriginUnknown,
		EvidenceKind: EvidenceObserved,
	}
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, wafBlocked),
		collResult(MechanismIndependentSensor, CoverageFound, sensorAllowed),
	})
	if v.EnforcementAx.State != AxisContradictory {
		t.Errorf("enforcement state = %q, want contradictory", v.EnforcementAx.State)
	}
}
```

- [ ] **Step 10: Run both contradiction tests to verify they pass**

Run: `go test ./internal/wafval/... -run TestCorrelate_CrossMechanism`
Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add internal/wafval/correlate.go internal/wafval/correlate_test.go internal/wafval/support_test.go
git commit -m "feat(wafval): per-axis correlation with dedup, ambiguity, contradiction

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `EvaluateClaim` — completeness, confidence, verdict derivation

**Files:**
- Create: `internal/wafval/evaluate.go`
- Create: `internal/wafval/evaluate_test.go`

**Interfaces:**
- Consumes: Task 1 types, Task 4 `Correlate`/`CorrelatedView`.
- Produces:
  - `Result{Key CorrelationKey; Expectation Expectation; View CorrelatedView; Completeness EvidenceCompleteness; Confidence Confidence; Verdict Verdict; Reason string}`
  - `func EvaluateClaim(exp Expectation, results []CollectionResult, key CorrelationKey) Result`
  - `func deriveCompleteness(claim ClaimType, results []CollectionResult) EvidenceCompleteness`
  - `func deriveConfidence(c EvidenceCompleteness, view CorrelatedView, results []CollectionResult) Confidence`

Derivation order inside `EvaluateClaim` (spec §9):
1. `Correlate` the results into a view.
2. `deriveCompleteness` from coverage tiers.
3. `deriveConfidence` from the completeness ceiling, downgraded by contradiction and inferred-only evidence.
4. Guard A: if the claim-relevant axis is `AxisContradictory` → `Inconclusive`.
5. Guard B: if `Completeness == CompletenessInsufficient` → `Inconclusive`.
6. Per-claim `deriveVerdict`.
7. Every returned `Result` must satisfy `Valid(claim, verdict, completeness)`; a panic here is a programming error (never expected to fire), so assert it in tests rather than returning an error.

Completeness tiers (spec §7, §8):
- `ClaimPrevention`: minimum = `MechanismWAFEngine` present; corroborating = `MechanismOriginApp`. Complete = WAF present AND origin present; Partial = WAF present, origin absent; Insufficient = WAF absent.
- `ClaimFalsePositive`: minimum = `MechanismWAFEngine`; no corroborating. Complete = WAF present; Insufficient = WAF absent.
- (`ClaimPolicyGap` completeness is per-leg; `deriveCompleteness` is not called for the pair itself — Task 6.)

Confidence (spec §7): ceiling by completeness (`Complete`→`High`, `Partial`→`Medium`, `Insufficient`→`None`); then downgrade: any contradictory claim-relevant axis → `None`; if the minimum mechanism's only contributing observation(s) are `EvidenceInferred` → cap at `Medium`.

- [ ] **Step 1: Write the failing test — Prevention blocked, both mechanisms, High**

```go
package wafval

import "testing"

func TestEvaluateClaim_PreventionBlocked_CompleteHigh(t *testing.T) {
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention, PolicyBasis: "CRS 942100 SQLi"},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
			collResult(MechanismOriginApp, CoverageSearchedVerifiedNone, originObs(OriginNotObserved)),
		},
		testKey(),
	)
	if r.Verdict != VerdictBlocked {
		t.Errorf("verdict = %q, want blocked", r.Verdict)
	}
	if r.Completeness != CompletenessComplete {
		t.Errorf("completeness = %q, want complete", r.Completeness)
	}
	if r.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high", r.Confidence)
	}
	if err := Valid(r.Expectation.Claim, r.Verdict, r.Completeness); err != nil {
		t.Errorf("result violates Valid: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/wafval/... -run TestEvaluateClaim_PreventionBlocked_CompleteHigh`
Expected: FAIL — `EvaluateClaim` undefined.

- [ ] **Step 3: Implement `EvaluateClaim`, `deriveCompleteness`, `deriveConfidence`, `deriveVerdict`**

```go
package wafval

// Result is one claim's graded outcome. Verdict is derived, never set by an
// adapter; the raw view and the three independent dimensions are all preserved.
type Result struct {
	Key          CorrelationKey
	Expectation  Expectation
	View         CorrelatedView
	Completeness EvidenceCompleteness
	Confidence   Confidence
	Verdict      Verdict
	Reason       string
}

// EvaluateClaim grades one claim against collected evidence. Pure over its
// inputs: no I/O, no clock, no hidden state.
func EvaluateClaim(exp Expectation, results []CollectionResult, key CorrelationKey) Result {
	view := Correlate(key, results)
	comp := deriveCompleteness(exp.Claim, results)
	conf := deriveConfidence(exp.Claim, comp, view, results)
	r := Result{Key: key, Expectation: exp, View: view, Completeness: comp, Confidence: conf}

	switch {
	case claimAxisContradictory(exp.Claim, view):
		r.Verdict, r.Reason = VerdictInconclusive, "claim-relevant evidence is contradictory across mechanisms"
	case comp == CompletenessInsufficient:
		r.Verdict, r.Reason = VerdictInconclusive, "insufficient evidence to render a verdict"
	default:
		r.Verdict, r.Reason = deriveVerdict(exp.Claim, view, comp)
	}
	if err := Valid(exp.Claim, r.Verdict, r.Completeness); err != nil {
		panic("wafval: derived an invalid verdict/claim/completeness: " + err.Error())
	}
	return r
}

func present(results []CollectionResult, m Mechanism) bool {
	for _, r := range results {
		if r.Mechanism == m && r.Coverage.Present() {
			return true
		}
	}
	return false
}

func deriveCompleteness(claim ClaimType, results []CollectionResult) EvidenceCompleteness {
	wafPresent := present(results, MechanismWAFEngine)
	switch claim {
	case ClaimPrevention:
		if !wafPresent {
			return CompletenessInsufficient
		}
		if present(results, MechanismOriginApp) {
			return CompletenessComplete
		}
		return CompletenessPartial
	case ClaimFalsePositive:
		if !wafPresent {
			return CompletenessInsufficient
		}
		return CompletenessComplete
	default:
		if !wafPresent {
			return CompletenessInsufficient
		}
		return CompletenessPartial
	}
}

func ceiling(c EvidenceCompleteness) Confidence {
	switch c {
	case CompletenessComplete:
		return ConfidenceHigh
	case CompletenessPartial:
		return ConfidenceMedium
	default:
		return ConfidenceNone
	}
}

func deriveConfidence(claim ClaimType, c EvidenceCompleteness, view CorrelatedView, results []CollectionResult) Confidence {
	conf := ceiling(c)
	if claimAxisContradictory(claim, view) {
		return ConfidenceNone
	}
	// Inferred-only minimum evidence caps at Medium.
	if minimumInferredOnly(results) && confRank(conf) > confRank(ConfidenceMedium) {
		conf = ConfidenceMedium
	}
	return conf
}

func confRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// minimumInferredOnly reports whether the WAF-engine mechanism contributed only
// inferred observations (no observed evidence at all).
func minimumInferredOnly(results []CollectionResult) bool {
	sawWAF, sawObserved := false, false
	for _, r := range results {
		if r.Mechanism != MechanismWAFEngine {
			continue
		}
		for _, o := range r.Observations {
			sawWAF = true
			if o.EvidenceKind == EvidenceObserved {
				sawObserved = true
			}
		}
	}
	return sawWAF && !sawObserved
}

// claimAxisContradictory reports whether an axis the claim depends on is
// contradictory. Prevention/PolicyGap depend on enforcement + detection;
// FalsePositive depends on enforcement only.
func claimAxisContradictory(claim ClaimType, view CorrelatedView) bool {
	if view.EnforcementAx.State == AxisContradictory {
		return true
	}
	if claim != ClaimFalsePositive && view.DetectionAx.State == AxisContradictory {
		return true
	}
	return false
}

// deriveVerdict is the per-claim switch. Guards A and B have already run, so
// completeness is never Insufficient and no claim-relevant axis is
// contradictory here.
func deriveVerdict(claim ClaimType, view CorrelatedView, c EvidenceCompleteness) (Verdict, string) {
	switch claim {
	case ClaimPrevention:
		return derivePrevention(view)
	case ClaimFalsePositive:
		return deriveFalsePositive(view)
	default:
		// PolicyGap legs are evaluated as Prevention; the pair rule lives in
		// EvaluatePolicyGap. A bare PolicyGap claim here is treated as a
		// single Prevention-shaped leg.
		return derivePrevention(view)
	}
}

func derivePrevention(view CorrelatedView) (Verdict, string) {
	enf := view.EnforcementAx
	det := view.DetectionAx
	if enf.State == AxisAgree && enf.Enforcement == EnforcementBlocked {
		return VerdictBlocked, "WAF enforced a block"
	}
	if enf.State == AxisAgree && enf.Enforcement == EnforcementAllowed {
		switch {
		case det.State == AxisAgree && det.Detection == DetectionMatched:
			return VerdictDetectedButAllowed, "request detected but allowed through (enforcement gap)"
		case det.State == AxisAgree && det.Detection == DetectionNotMatched:
			return VerdictMissed, "request neither detected nor blocked (detection + enforcement gap)"
		default:
			return VerdictInconclusive, "allowed, but detection state could not be established"
		}
	}
	return VerdictInconclusive, "enforcement action could not be established"
}

func deriveFalsePositive(view CorrelatedView) (Verdict, string) {
	enf := view.EnforcementAx
	if enf.State != AxisAgree {
		return VerdictInconclusive, "enforcement action could not be established"
	}
	switch enf.Enforcement {
	case EnforcementAllowed:
		return VerdictAllowed, "legitimate request correctly allowed"
	case EnforcementBlocked, EnforcementChallenged, EnforcementTerminated:
		return VerdictIncorrectlyBlocked, "legitimate request incorrectly blocked (false positive)"
	default:
		return VerdictInconclusive, "enforcement action could not be established"
	}
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/wafval/... -run TestEvaluateClaim_PreventionBlocked_CompleteHigh`
Expected: PASS.

- [ ] **Step 5: Write the remaining evaluate tests**

```go
func TestEvaluateClaim_FalsePositiveAllowed(t *testing.T) {
	r := EvaluateClaim(
		Expectation{Claim: ClaimFalsePositive, PolicyBasis: "legit login"},
		[]CollectionResult{collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementAllowed, DetectionNotMatched))},
		testKey(),
	)
	if r.Verdict != VerdictAllowed {
		t.Errorf("verdict = %q, want allowed", r.Verdict)
	}
}

func TestEvaluateClaim_PreventionAllowed_NeverVerdictAllowed(t *testing.T) {
	// Same enforcement=allowed, but a Prevention claim must NEVER return Allowed.
	matched := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementAllowed, DetectionMatched)),
			collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
		},
		testKey(),
	)
	if matched.Verdict == VerdictAllowed {
		t.Fatal("Prevention claim returned VerdictAllowed — forbidden")
	}
	if matched.Verdict != VerdictDetectedButAllowed {
		t.Errorf("verdict = %q, want detected_but_allowed", matched.Verdict)
	}
	missed := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageSearchedVerifiedNone, wafEngineObs(EnforcementAllowed, DetectionNotMatched)),
			collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
		},
		testKey(),
	)
	if missed.Verdict != VerdictMissed {
		t.Errorf("verdict = %q, want missed", missed.Verdict)
	}
}

func TestEvaluateClaim_WAFOnly_CapsAtMedium(t *testing.T) {
	// Origin telemetry unavailable: still reaches Blocked, but never High.
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
			collResult(MechanismOriginApp, CoverageSourceUnavailable),
		},
		testKey(),
	)
	if r.Verdict != VerdictBlocked {
		t.Errorf("verdict = %q, want blocked", r.Verdict)
	}
	if r.Completeness != CompletenessPartial {
		t.Errorf("completeness = %q, want partial", r.Completeness)
	}
	if r.Confidence == ConfidenceHigh {
		t.Error("confidence reached High on WAF-only evidence — must be capped")
	}
}

func TestEvaluateClaim_ContradictionForcesInconclusive(t *testing.T) {
	sensorAllowed := Observation{
		Mechanism: MechanismIndependentSensor, Provider: "lab-pcap", EventID: "pcap-1",
		RequestID: "req-1", Enforcement: EnforcementAllowed, Detection: DetectionUnknown, Origin: OriginUnknown,
		EvidenceKind: EvidenceObserved,
	}
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
			collResult(MechanismIndependentSensor, CoverageFound, sensorAllowed),
		},
		testKey(),
	)
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (contradiction)", r.Verdict)
	}
	if r.Confidence != ConfidenceNone {
		t.Errorf("confidence = %q, want none despite complete collection", r.Confidence)
	}
}

func TestEvaluateClaim_NoObservations_Inconclusive(t *testing.T) {
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, nil, testKey())
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", r.Verdict)
	}
	if r.Completeness != CompletenessInsufficient {
		t.Errorf("completeness = %q, want insufficient", r.Completeness)
	}
}

func TestEvaluateClaim_IncompleteCoverage_CannotEstablishMissed(t *testing.T) {
	// WAF allowed, but detection search was incomplete: cannot assert not_matched,
	// so cannot be Missed. Detection is Unknown -> Inconclusive.
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageSearchIncomplete, wafEngineObs(EnforcementAllowed, DetectionUnknown)),
			collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
		},
		testKey(),
	)
	if r.Verdict == VerdictMissed {
		t.Fatal("incomplete coverage must never establish Missed")
	}
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", r.Verdict)
	}
}
```

Note on the `IncompleteCoverage` case: WAF coverage is `search_incomplete`, so `present()` is false for WAF → completeness `Insufficient` → Guard B fires → `Inconclusive`. This proves incomplete coverage cannot yield `Missed` via the completeness path. The detection=`DetectionUnknown` also independently blocks `Missed` in `derivePrevention`. Both guard it.

- [ ] **Step 6: Run the full evaluate test file to verify all pass**

Run: `go test ./internal/wafval/... -run TestEvaluateClaim`
Expected: PASS (all 7 `TestEvaluateClaim_*`).

- [ ] **Step 7: Commit**

```bash
git add internal/wafval/evaluate.go internal/wafval/evaluate_test.go
git commit -m "feat(wafval): claim evaluation, completeness/confidence/verdict derivation

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: `EvaluatePolicyGap` — baseline/weakened pair rule

**Files:**
- Create: `internal/wafval/policygap.go`
- Create: `internal/wafval/policygap_test.go`

**Interfaces:**
- Consumes: Task 1 types, Task 5 `Result`/`EvaluateClaim`.
- Produces:
  - `Pair{Baseline, Weakened Result; PolicyDifferentiationConfirmed bool}`
  - `func EvaluatePolicyGap(p Pair) (Verdict, string)`

Rules (spec §10), first match wins:
```
!PolicyDifferentiationConfirmed                    -> Inconclusive ("policy change not confirmed in force")
baseline not trustworthy Blocked                   -> Inconclusive ("baseline did not establish a reliable block")
baseline Blocked & weakened Missed                 -> Missed             ("enforcement AND detection gap, attributable to policy weakening")
baseline Blocked & weakened DetectedButAllowed     -> DetectedButAllowed ("enforcement weakness; detection still fired")
baseline Blocked & weakened Blocked                -> Blocked            ("no gap demonstrated under this weakening")
otherwise                                          -> Inconclusive ("weakened-leg outcome not attributable")
```
"Trustworthy Blocked" = `baseline.Verdict == VerdictBlocked && confRank(baseline.Confidence) >= confRank(ConfidenceMedium)`.

- [ ] **Step 1: Write the failing test — strong policy-gap finding**

```go
package wafval

import "testing"

func blockedResult(conf Confidence) Result {
	return Result{Expectation: Expectation{Claim: ClaimPrevention}, Verdict: VerdictBlocked, Confidence: conf, Completeness: CompletenessComplete}
}
func missedResult() Result {
	return Result{Expectation: Expectation{Claim: ClaimPrevention}, Verdict: VerdictMissed, Confidence: ConfidenceHigh, Completeness: CompletenessComplete}
}

func TestEvaluatePolicyGap_StrongGap(t *testing.T) {
	v, reason := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceHigh),
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictMissed {
		t.Errorf("verdict = %q, want missed", v)
	}
	if reason == "" {
		t.Error("reason must name the policy attribution")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/wafval/... -run TestEvaluatePolicyGap_StrongGap`
Expected: FAIL — `EvaluatePolicyGap`/`Pair` undefined.

- [ ] **Step 3: Implement `Pair` and `EvaluatePolicyGap`**

```go
package wafval

// Pair holds the two Prevention-shaped legs of a policy-gap comparison plus
// explicit confirmation that the weakened policy was actually in force. The raw
// Results are never mutated.
type Pair struct {
	Baseline                       Result
	Weakened                       Result
	PolicyDifferentiationConfirmed bool
}

func trustworthyBlocked(r Result) bool {
	return r.Verdict == VerdictBlocked && confRank(r.Confidence) >= confRank(ConfidenceMedium)
}

// EvaluatePolicyGap derives the pair verdict. It depends on both legs' observed
// behavior, the baseline's evidence quality, and confirmation that the policy
// difference was applied. Every verdict carries a Reason naming the attribution.
func EvaluatePolicyGap(p Pair) (Verdict, string) {
	if !p.PolicyDifferentiationConfirmed {
		return VerdictInconclusive, "policy change not confirmed in force; differing responses not attributable to the weakening"
	}
	if !trustworthyBlocked(p.Baseline) {
		return VerdictInconclusive, "baseline did not establish a reliable block; weakened-leg behavior cannot be attributed to the policy change"
	}
	switch p.Weakened.Verdict {
	case VerdictMissed:
		return VerdictMissed, "enforcement and detection gap, attributable to policy weakening (confirmed via baseline comparison)"
	case VerdictDetectedButAllowed:
		return VerdictDetectedButAllowed, "enforcement weakness; detection still fired, attributable to policy weakening (confirmed via baseline comparison)"
	case VerdictBlocked:
		return VerdictBlocked, "no gap demonstrated under this weakening; weakened policy still blocked"
	default:
		return VerdictInconclusive, "weakened-leg outcome not attributable to the policy change"
	}
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/wafval/... -run TestEvaluatePolicyGap_StrongGap`
Expected: PASS.

- [ ] **Step 5: Write the remaining policy-gap tests**

```go
func TestEvaluatePolicyGap_UnconfirmedDifferentiation_Inconclusive(t *testing.T) {
	// Legs differ, but the policy change was not confirmed in force.
	v, _ := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceHigh),
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: false,
	})
	if v != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", v)
	}
}

func TestEvaluatePolicyGap_UntrustworthyBaseline_Inconclusive(t *testing.T) {
	inconclusiveBaseline := Result{Verdict: VerdictInconclusive, Confidence: ConfidenceNone}
	v, _ := EvaluatePolicyGap(Pair{
		Baseline:                       inconclusiveBaseline,
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (untrustworthy baseline)", v)
	}
}

func TestEvaluatePolicyGap_EnforcementWeaknessNotDetectionGap(t *testing.T) {
	detectedButAllowed := Result{Verdict: VerdictDetectedButAllowed, Confidence: ConfidenceHigh, Completeness: CompletenessComplete}
	v, reason := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceHigh),
		Weakened:                       detectedButAllowed,
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictDetectedButAllowed {
		t.Errorf("verdict = %q, want detected_but_allowed", v)
	}
	if reason == "" {
		t.Error("reason must distinguish enforcement weakness from detection gap")
	}
}

func TestEvaluatePolicyGap_LowConfidenceBaseline_Inconclusive(t *testing.T) {
	v, _ := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceLow),
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (baseline Blocked but Low confidence)", v)
	}
}
```

- [ ] **Step 6: Run the full policy-gap test file to verify all pass**

Run: `go test ./internal/wafval/... -run TestEvaluatePolicyGap`
Expected: PASS (all 5 `TestEvaluatePolicyGap_*`).

- [ ] **Step 7: Commit**

```bash
git add internal/wafval/policygap.go internal/wafval/policygap_test.go
git commit -m "feat(wafval): policy-gap pair evaluation with confirmed differentiation

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: `NotTested` distinction + full-package gate

**Files:**
- Modify: `internal/wafval/evaluate_test.go` (add the NotTested-distinction test)

**Interfaces:**
- Consumes: Task 5 `EvaluateClaim`.
- Produces: nothing new; this task closes acceptance-gate item 7 and runs the whole-package suite.

The spec is explicit (§11): `NotTested` is a catalog status *above* the evaluator, not a `Verdict`. The proof is twofold: (a) there is no `VerdictNotTested` constant (compile-time — grep), and (b) the moment an attempt is recorded with zero usable observations, the evaluator returns `Inconclusive`, never reverting to a not-tested state. Part (b) is `TestEvaluateClaim_NoObservations_Inconclusive` from Task 5; part (a) is a new guard test.

- [ ] **Step 1: Write the failing test — no NotTested verdict exists / evaluator never emits it**

```go
func TestResult_NotTestedDistinctFromInconclusive(t *testing.T) {
	// Executed-but-empty attempt -> Inconclusive (a Result exists).
	executed := EvaluateClaim(Expectation{Claim: ClaimPrevention}, []CollectionResult{
		collResult(MechanismWAFEngine, CoverageSourceUnavailable),
	}, testKey())
	if executed.Verdict != VerdictInconclusive {
		t.Errorf("executed-but-empty verdict = %q, want inconclusive", executed.Verdict)
	}
	// The evaluator must never emit a not-tested-like verdict. Every verdict it
	// can return is one of the six terminal Verdict values; none is "not_tested".
	for _, v := range []Verdict{
		VerdictBlocked, VerdictDetectedButAllowed, VerdictMissed,
		VerdictIncorrectlyBlocked, VerdictAllowed, VerdictInconclusive,
	} {
		if string(v) == "not_tested" {
			t.Fatal("not_tested must not be a Verdict value")
		}
	}
}
```

- [ ] **Step 2: Run it to verify it passes**

Run: `go test ./internal/wafval/... -run TestResult_NotTestedDistinctFromInconclusive`
Expected: PASS. (This is a guard, not a RED-first driver — the distinction is structural. If it fails, a `VerdictNotTested` was wrongly added; remove it.)

- [ ] **Step 3: Run the whole-package suite**

Run: `go test ./internal/wafval/...`
Expected: PASS, all tests, no build warnings.

- [ ] **Step 4: Run build + vet across the module to confirm no import leakage**

Run: `go build ./... && go vet ./internal/wafval/...`
Expected: both clean. (A dependency on `internal/controlval` or any vendor type would surface here and in review.)

- [ ] **Step 5: Verify the no-forbidden-import constraint explicitly**

Run: `go list -deps ./internal/wafval | grep -E 'controlval|adefficacy' || echo "CLEAN: no forbidden imports"`
Expected: `CLEAN: no forbidden imports`.

- [ ] **Step 6: Commit**

```bash
git add internal/wafval/evaluate_test.go
git commit -m "test(wafval): NotTested-vs-Inconclusive distinction, full-package gate

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Acceptance Gate Traceability (spec §13 → task/test)

| # | Spec §13 test | Task | Test name |
|---|---|---|---|
| 1 | Prevention malicious → Blocked/High | 5 | `TestEvaluateClaim_PreventionBlocked_CompleteHigh` |
| 2 | FalsePositive legit → Allowed | 5 | `TestEvaluateClaim_FalsePositiveAllowed` |
| 3 | PolicyGap weakened → Missed w/ attribution | 6 | `TestEvaluatePolicyGap_StrongGap` |
| 4 | PolicyGap untrustworthy baseline → Inconclusive | 6 | `TestEvaluatePolicyGap_UntrustworthyBaseline_Inconclusive` |
| 5 | WAF-only, origin unavailable → Blocked, < High | 5 | `TestEvaluateClaim_WAFOnly_CapsAtMedium` |
| 6 | Complete-but-contradictory → None/Inconclusive | 5 | `TestEvaluateClaim_ContradictionForcesInconclusive` |
| 7 | NotTested distinct from Inconclusive | 7 / 5 | `TestResult_NotTestedDistinctFromInconclusive` / `TestEvaluateClaim_NoObservations_Inconclusive` |
| 8 | Valid rejects invalid pairs | 1 | `TestValid` |
| 9 | Detection/enforcement vary independently | 5 | `TestEvaluateClaim_PreventionAllowed_NeverVerdictAllowed` (matched→DetectedButAllowed vs not_matched→Missed) |
| 10 | Incomplete coverage cannot establish Missed | 5 | `TestEvaluateClaim_IncompleteCoverage_CannotEstablishMissed` |
| 11 | Duplicate EventID not independent corroboration | 4 | `TestCorrelate_DuplicateEventID_NotIndependentCorroboration` |
| 12 | Same-mechanism disagreement → ambiguity | 4 | `TestCorrelate_SameMechanismDisagreement_Ambiguous` |
| 13 | PolicyGap unconfirmed differentiation → Inconclusive | 6 | `TestEvaluatePolicyGap_UnconfirmedDifferentiation_Inconclusive` |
| 14 | Prevention allowed never → Allowed | 5 | `TestEvaluateClaim_PreventionAllowed_NeverVerdictAllowed` |
