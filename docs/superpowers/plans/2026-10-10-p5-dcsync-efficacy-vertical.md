# Phase 5 — DCSync Control-Efficacy Vertical Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build the thin, fake-backed, lab-gated vertical that validates whether AD's native replication-rights control prevents DCSync by an unauthorized principal, mapped through `controlval`/`adcontrolval`.

**Architecture:** New package `internal/adefficacy`: a `NativeADProvider` (implements `controlval.Provider`) behind a `ControlDecisionSource` seam that reports the DC's DRSUAPI result (primary) + event-4662 corroboration (secondary); the two per-principal expectations; a correlation helper; and a trust-pairing gate. No real source, no live wiring.

**Tech Stack:** Go (`github.com/audspect/bas`), stdlib `testing`. `go test ./internal/adefficacy/` from `orchestrator/`.

**Spec:** `docs/superpowers/specs/2026-10-10-p5-dcsync-efficacy-vertical-design.md`

**Execution:** Native/inline — decided.

## Global Constraints

- `internal/adefficacy` imports `controlval` + `adcontrolval` + `adprimitive` + stdlib only. No `adlabrt`, no vendor, no DB. `controlval`/`adcontrolval`/`admatrix` do not import it.
- DRSUAPI result is the **sole determinant of Outcome**; 4662 is corroboration only and **never** establishes an outcome alone. `EvidenceKind` is always `observed`.
- Confidence: uncorrelated → `None`; DRSUAPI indeterminate → `None`; correlated + DRSUAPI conclusive → `High` (4662 state recorded in Detail, never lowers below High).
- `PolicyVerified` is always `false` in this slice (lab intended config, not independently verified).
- Fail-closed: indeterminate / uncorrelated / 4662-only → `SKIPPED` (via `controlval.Evaluate`), never `PASS`.
- Trust pairing never mutates raw `Validation`s and never upgrades a verdict.
- No `dispatchRun`/`CapabilityStates()` wiring; no real `ControlDecisionSource`.
- Commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`; push after every commit.

## Review Focus

- **4662 drives an outcome** (spec §2): a present 4662 with indeterminate DRSUAPI must stay `Unknown`/`SKIPPED`, never `Blocked` — `TestObserve_Event4662AloneDoesNotEstablishBlocked` (Task 1).
- **Uncorrelated decision promoted** (spec §2): not-correlated → `None` confidence → `SKIPPED` — `TestObserve_UncorrelatedIsNoneConfidence` (Task 1).
- **Negative PASS trusted while positive failed** (spec §4): `AcceptedNegativeVerdict` downgrades to `SKIPPED` — `TestPair_NegativePassNotTrustedWhenPositiveNotPass` (Task 3).
- **Trust gate mutates/upgrades raw evidence** (spec §4): raw `Validation`s unchanged; never upgrades — `TestPair_DoesNotMutateRawOrUpgrade` (Task 3).
- **PolicyVerified leaks true** (spec §3): both expectations carry `PolicyVerified=false` — `TestExpectations_PolicyNotVerified` (Task 2).

---

### Task 1: `NativeADProvider` + `ControlDecisionSource` seam

**Files:**
- Create: `orchestrator/internal/adefficacy/provider.go`
- Test: `orchestrator/internal/adefficacy/provider_test.go`, `orchestrator/internal/adefficacy/support_test.go`

**Interfaces:**
- Consumes: `controlval.{Observation, CorrelationKey, Outcome*, EvidenceObserved, Confidence*, Provider}` (existing).
- Produces:
  - `type DRSUAPIResult string` (`DRSUAPIAccessDenied="access_denied"`, `DRSUAPISucceeded="succeeded"`, `DRSUAPIIndeterminate="indeterminate"`).
  - `type Corroboration string` (`Corroborated="corroborated"`, `Uncorroborated="uncorroborated"`, `CorroborationUnknown="unknown"`).
  - `type ControlDecision struct { DRSUAPI DRSUAPIResult; Audit4662 Corroboration; Correlated bool; Detail string }`.
  - `type ControlDecisionSource interface { Decision(ctx context.Context, key controlval.CorrelationKey) (ControlDecision, error) }`.
  - `type NativeADProvider struct { Src ControlDecisionSource; Clock func() time.Time }` with `Name() string` (returns `"native-ad"`) and `Observe(ctx, key) (controlval.Observation, error)`.

- [ ] **Step 1: Write the failing tests + fake source**

`support_test.go`:
```go
package adefficacy

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
)

type fakeSource struct {
	dec ControlDecision
	err error
}

func (f fakeSource) Decision(context.Context, controlval.CorrelationKey) (ControlDecision, error) {
	return f.dec, f.err
}
```

`provider_test.go`:
```go
package adefficacy

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func observe(t *testing.T, d ControlDecision, err error) (controlval.Observation, error) {
	t.Helper()
	p := &NativeADProvider{Src: fakeSource{dec: d, err: err}}
	return p.Observe(context.Background(), controlval.CorrelationKey{RunID: "r1", Target: "dc01", Action: "dcsync"})
}

func TestObserve_AccessDeniedIsBlockedObservedHigh(t *testing.T) {
	got, err := observe(t, ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Corroborated, Correlated: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != controlval.OutcomeBlocked || got.EvidenceKind != controlval.EvidenceObserved || got.Confidence != controlval.ConfidenceHigh {
		t.Fatalf("got %+v, want blocked/observed/high", got)
	}
	if got.Provider != "native-ad" {
		t.Fatalf("provider = %q", got.Provider)
	}
}

func TestObserve_SucceededIsAllowedHigh(t *testing.T) {
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPISucceeded, Audit4662: Corroborated, Correlated: true}, nil)
	if got.Outcome != controlval.OutcomeAllowed || got.Confidence != controlval.ConfidenceHigh {
		t.Fatalf("got %+v, want allowed/high", got)
	}
}

func TestObserve_ConclusiveWithoutCorroborationStaysHigh(t *testing.T) {
	// DRSUAPI is the authoritative primary; a missing 4662 must NOT lower it.
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Uncorroborated, Correlated: true}, nil)
	if got.Outcome != controlval.OutcomeBlocked || got.Confidence != controlval.ConfidenceHigh {
		t.Fatalf("got %+v, want blocked/high (DRSUAPI primary, 4662 optional)", got)
	}
}

func TestObserve_Event4662AloneDoesNotEstablishBlocked(t *testing.T) {
	// Indeterminate DRSUAPI + present 4662 must stay Unknown, never Blocked.
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPIIndeterminate, Audit4662: Corroborated, Correlated: true}, nil)
	if got.Outcome != controlval.OutcomeUnknown {
		t.Fatalf("outcome = %q, want unknown (4662 alone never establishes blocked)", got.Outcome)
	}
}

func TestObserve_UncorrelatedIsNoneConfidence(t *testing.T) {
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Corroborated, Correlated: false}, nil)
	if got.Confidence != controlval.ConfidenceNone {
		t.Fatalf("confidence = %q, want none (uncorrelated)", got.Confidence)
	}
}

func TestObserve_SourceErrorPropagates(t *testing.T) {
	if _, err := observe(t, ControlDecision{}, errors.New("winrm down")); err == nil {
		t.Fatal("expected source error to propagate (-> ERROR via Evaluate)")
	}
}

func TestNativeADProvider_SatisfiesProvider(t *testing.T) {
	var _ controlval.Provider = (*NativeADProvider)(nil)
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./internal/adefficacy/`
Expected: FAIL — undefined `NativeADProvider`, `ControlDecision`, etc.

- [ ] **Step 3: Implement**

```go
// Package adefficacy is the first real control-efficacy vertical: it validates
// whether AD's native directory-replication-rights control prevents DCSync by
// an unauthorized principal. It is thin and lab-gated -- it ships a fake-backed
// ControlDecisionSource only; the real source (reading a live DC via
// adlabhyperv) and any CapabilityStates()/dispatchRun wiring are deferred until
// a lab run is authorized.
package adefficacy

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// DRSUAPIResult is the PRIMARY enforcement evidence: the replication call's own
// result. It alone determines the control Outcome.
type DRSUAPIResult string

const (
	DRSUAPIAccessDenied  DRSUAPIResult = "access_denied"
	DRSUAPISucceeded     DRSUAPIResult = "succeeded"
	DRSUAPIIndeterminate DRSUAPIResult = "indeterminate"
)

// Corroboration is the SECONDARY signal (Windows Security event 4662). It may
// support a result but NEVER establishes an outcome on its own.
type Corroboration string

const (
	Corroborated         Corroboration = "corroborated"
	Uncorroborated       Corroboration = "uncorroborated"
	CorroborationUnknown Corroboration = "unknown"
)

// ControlDecision is the native AD control's enforcement decision for one
// DCSync attempt, as read from the lab.
type ControlDecision struct {
	DRSUAPI    DRSUAPIResult
	Audit4662  Corroboration
	Correlated bool
	Detail     string
}

// ControlDecisionSource is the seam the real lab implements to report a DC's
// enforcement decision. A fake implements it for tests; no real implementation
// ships in this slice.
type ControlDecisionSource interface {
	Decision(ctx context.Context, key controlval.CorrelationKey) (ControlDecision, error)
}

// NativeADProvider adapts a ControlDecisionSource to controlval.Provider.
type NativeADProvider struct {
	Src   ControlDecisionSource
	Clock func() time.Time
}

// Name identifies this provider.
func (p *NativeADProvider) Name() string { return "native-ad" }

// Observe reads the DC's decision and maps it to a controlval.Observation. The
// DRSUAPI result is the sole determinant of Outcome; the 4662 corroboration
// only affects Detail, never the outcome, and never raises/establishes it.
func (p *NativeADProvider) Observe(ctx context.Context, key controlval.CorrelationKey) (controlval.Observation, error) {
	d, err := p.Src.Decision(ctx, key)
	if err != nil {
		return controlval.Observation{}, err
	}
	obs := controlval.Observation{
		Key:          key,
		Provider:     p.Name(),
		EvidenceKind: controlval.EvidenceObserved,
		Confidence:   confidenceFor(d),
		Source:       "drsuapi+4662",
		Detail:       d.Detail + " [4662=" + string(d.Audit4662) + "]",
	}
	if p.Clock != nil {
		obs.ObservedAt = p.Clock()
	}
	switch d.DRSUAPI {
	case DRSUAPIAccessDenied:
		obs.Outcome = controlval.OutcomeBlocked
	case DRSUAPISucceeded:
		obs.Outcome = controlval.OutcomeAllowed
	default:
		obs.Outcome = controlval.OutcomeUnknown
	}
	return obs, nil
}

// confidenceFor grades correlation + primary-evidence quality. DRSUAPI is
// authoritative: a conclusive, correlated result is High regardless of 4662.
// Anything short fails closed to None.
func confidenceFor(d ControlDecision) controlval.Confidence {
	if !d.Correlated || d.DRSUAPI == DRSUAPIIndeterminate {
		return controlval.ConfidenceNone
	}
	return controlval.ConfidenceHigh
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./internal/adefficacy/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adefficacy/provider.go orchestrator/internal/adefficacy/provider_test.go orchestrator/internal/adefficacy/support_test.go
git commit -m "feat(adefficacy): native-AD-control provider + ControlDecisionSource seam

DRSUAPI result is the sole outcome determinant; 4662 is corroboration only
(never establishes an outcome, never lowers a conclusive primary). Uncorrelated
or indeterminate -> None confidence -> SKIPPED upstream. Fake-backed only.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

### Task 2: DCSync expectations + correlation + end-to-end evaluate

**Files:**
- Create: `orchestrator/internal/adefficacy/dcsync.go`
- Test: `orchestrator/internal/adefficacy/dcsync_test.go`

**Interfaces:**
- Consumes: Task 1 types; `controlval.{Expectation, Evaluate, Outcome*, Confidence*, Verdict*, TimeWindow, CorrelationKey}`; `adcontrolval.CorrelationKeyFor`; `adprimitive.{Primitive, DCSyncCatalog}`.
- Produces:
  - `const PrincipalAttacker = "attacker"`, `PrincipalLabuser = "labuser"`.
  - `func DCSyncPrimitive() adprimitive.Primitive` (the real `dcsync` catalog entry).
  - `func KeyFor(runID, target string, window controlval.TimeWindow) controlval.CorrelationKey`.
  - `func NegativeExpectation() controlval.Expectation`, `func PositiveExpectation() controlval.Expectation`.

- [ ] **Step 1: Write the failing tests**

```go
package adefficacy

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestDCSyncPrimitive_IsCatalogEntry(t *testing.T) {
	if DCSyncPrimitive().ID != "dcsync" {
		t.Fatalf("id = %q, want dcsync", DCSyncPrimitive().ID)
	}
}

func TestKeyFor_UsesDcsyncAction(t *testing.T) {
	k := KeyFor("r1", "dc01", controlval.TimeWindow{})
	if k.Action != "dcsync" || k.RunID != "r1" || k.Target != "dc01" {
		t.Fatalf("key = %+v", k)
	}
}

func TestExpectations_PolicyNotVerified(t *testing.T) {
	for _, e := range []controlval.Expectation{NegativeExpectation(), PositiveExpectation()} {
		if e.PolicyVerified {
			t.Fatal("PolicyVerified must be false (lab intended config, not verified)")
		}
		if e.PolicyBasis == "" || e.MinConfidence != controlval.ConfidenceHigh {
			t.Fatalf("expectation under-specified: %+v", e)
		}
	}
	if NegativeExpectation().Expected != controlval.OutcomeBlocked {
		t.Fatal("negative must expect blocked")
	}
	if PositiveExpectation().Expected != controlval.OutcomeAllowed {
		t.Fatal("positive must expect allowed")
	}
}

func eval(t *testing.T, exp controlval.Expectation, d ControlDecision) controlval.Validation {
	t.Helper()
	p := &NativeADProvider{Src: fakeSource{dec: d}}
	obs, err := p.Observe(context.Background(), KeyFor("r1", "dc01", controlval.TimeWindow{}))
	return controlval.Evaluate(exp, &obs, err)
}

func TestEndToEnd_LabuserDeniedIsPass(t *testing.T) {
	v := eval(t, NegativeExpectation(), ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (control denied unauthorized DCSync)", v.Verdict)
	}
}

func TestEndToEnd_LabuserAllowedIsGapFail(t *testing.T) {
	v := eval(t, NegativeExpectation(), ControlDecision{DRSUAPI: DRSUAPISucceeded, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (unauthorized DCSync succeeded -- control gap)", v.Verdict)
	}
}

func TestEndToEnd_AttackerAllowedIsPass(t *testing.T) {
	v := eval(t, PositiveExpectation(), ControlDecision{DRSUAPI: DRSUAPISucceeded, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (authorized DCSync succeeded)", v.Verdict)
	}
}

func TestEndToEnd_IndeterminateIsSkipped(t *testing.T) {
	v := eval(t, NegativeExpectation(), ControlDecision{DRSUAPI: DRSUAPIIndeterminate, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (ambiguous evidence, no false protection claim)", v.Verdict)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./internal/adefficacy/ -run 'DCSyncPrimitive|KeyFor|Expectations|EndToEnd'`
Expected: FAIL — undefined `DCSyncPrimitive`, `KeyFor`, `NegativeExpectation`, `PositiveExpectation`.

- [ ] **Step 3: Implement**

```go
package adefficacy

import (
	"github.com/audspect/bas/internal/adcontrolval"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
)

// Principal identities under test (match the runbook §3.3).
const (
	PrincipalAttacker = "attacker" // positive control: replication rights granted
	PrincipalLabuser  = "labuser"  // negative control: no replication rights
)

// DCSyncPrimitive returns the real catalog dcsync primitive (T1003.006).
func DCSyncPrimitive() adprimitive.Primitive {
	for _, p := range adprimitive.DCSyncCatalog {
		if p.ID == "dcsync" {
			return p
		}
	}
	return adprimitive.Primitive{ID: "dcsync"} // defensive; catalog always has it
}

// KeyFor builds the correlation key for a DCSync attempt in a given run. Each
// principal runs under its own runID, so the key identifies the attempt.
func KeyFor(runID, target string, window controlval.TimeWindow) controlval.CorrelationKey {
	return adcontrolval.CorrelationKeyFor(DCSyncPrimitive(), runID, target, window)
}

// NegativeExpectation is the labuser case: no rights, so DCSync must be blocked.
func NegativeExpectation() controlval.Expectation {
	return controlval.Expectation{
		Expected:       controlval.OutcomeBlocked,
		PolicyBasis:    "LAB\\labuser holds neither DS-Replication-Get-Changes nor -All on the domain head",
		PolicyVerified: false,
		MinConfidence:  controlval.ConfidenceHigh,
	}
}

// PositiveExpectation is the attacker case: rights granted, so DCSync succeeds.
func PositiveExpectation() controlval.Expectation {
	return controlval.Expectation{
		Expected:       controlval.OutcomeAllowed,
		PolicyBasis:    "LAB\\attacker deliberately granted DS-Replication-Get-Changes[-All] (positive control)",
		PolicyVerified: false,
		MinConfidence:  controlval.ConfidenceHigh,
	}
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./internal/adefficacy/`
Expected: PASS (Task 1 + Task 2).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adefficacy/dcsync.go orchestrator/internal/adefficacy/dcsync_test.go
git commit -m "feat(adefficacy): DCSync expectations + correlation + end-to-end evaluate

Per-principal expectations (labuser->blocked, attacker->allowed; PolicyVerified
false); KeyFor via adcontrolval over the real dcsync primitive; end-to-end
fake->Observe->Evaluate verdicts incl. gap FAIL and ambiguous->SKIPPED.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

### Task 3: Trust pairing + axis mapping + lab-readiness checklist

**Files:**
- Create: `orchestrator/internal/adefficacy/pair.go`, `orchestrator/internal/adefficacy/pair_test.go`
- Modify: `docs/operations/p5-ad-lab-operator-runbook.md` (add a DCSync-efficacy readiness section)

**Interfaces:**
- Consumes: `controlval.{Validation, Verdict*}`; `adcontrolval.ToEfficacyState`; `admatrix.ControlEfficacyState`.
- Produces:
  - `type Pair struct { Positive, Negative controlval.Validation }`.
  - `func (p Pair) AcceptedNegativeVerdict() (controlval.Verdict, string)`.

- [ ] **Step 1: Write the failing tests**

```go
package adefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/adcontrolval"
	"github.com/audspect/bas/internal/controlval"
)

func pass() controlval.Validation {
	return controlval.Validation{Verdict: controlval.VerdictPass, Reason: "ok"}
}

func TestPair_NegativePassAcceptedWhenPositivePass(t *testing.T) {
	v, _ := Pair{Positive: pass(), Negative: pass()}.AcceptedNegativeVerdict()
	if v != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (positive succeeded, denial trustworthy)", v)
	}
}

func TestPair_NegativePassNotTrustedWhenPositiveNotPass(t *testing.T) {
	// Positive control FAILED: the negative denial must NOT be a trustworthy PASS.
	neg := pass()
	v, reason := Pair{Positive: controlval.Validation{Verdict: controlval.VerdictFail}, Negative: neg}.AcceptedNegativeVerdict()
	if v != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (harness not shown capable of success)", v)
	}
	if reason == "" {
		t.Fatal("downgrade must carry a reason")
	}
}

func TestPair_DoesNotMutateRawOrUpgrade(t *testing.T) {
	neg := pass()
	p := Pair{Positive: controlval.Validation{Verdict: controlval.VerdictFail}, Negative: neg}
	_, _ = p.AcceptedNegativeVerdict()
	if p.Negative.Verdict != controlval.VerdictPass {
		t.Fatal("raw negative Validation must be untouched")
	}
	// Never upgrades: a negative FAIL stays FAIL even if positive passed.
	v2, _ := Pair{Positive: pass(), Negative: controlval.Validation{Verdict: controlval.VerdictFail}}.AcceptedNegativeVerdict()
	if v2 != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (never upgraded)", v2)
	}
}

func TestMapping_ThroughAdcontrolvalIsFaithful(t *testing.T) {
	v := controlval.Validation{
		Verdict:     controlval.VerdictPass,
		Expectation: controlval.Expectation{Expected: controlval.OutcomeBlocked},
		Observation: &controlval.Observation{Provider: "native-ad", Outcome: controlval.OutcomeBlocked,
			EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}
	s := adcontrolval.ToEfficacyState(v)
	if !s.Evaluated || s.Verdict != "PASS" || s.Provider != "native-ad" || s.Observed != "blocked" {
		t.Fatalf("mapping not faithful: %+v", s)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./internal/adefficacy/ -run Pair`
Expected: FAIL — undefined `Pair`.

- [ ] **Step 3: Implement**

```go
package adefficacy

import "github.com/audspect/bas/internal/controlval"

// Pair holds the two independent principal results. The raw Validations are
// never mutated; the acceptance gate is a separate derivation.
type Pair struct {
	Positive controlval.Validation // attacker, expected allowed
	Negative controlval.Validation // labuser, expected blocked
}

// AcceptedNegativeVerdict returns the TRUSTWORTHY verdict for the negative
// control. A negative PASS is downgraded to SKIPPED when the positive control
// did not cleanly PASS -- a denial is only trustworthy once the harness is
// shown capable of an authorized success. It never upgrades and never mutates
// the raw Validations.
func (p Pair) AcceptedNegativeVerdict() (controlval.Verdict, string) {
	if p.Negative.Verdict == controlval.VerdictPass && p.Positive.Verdict != controlval.VerdictPass {
		return controlval.VerdictSkipped,
			"negative-control denial not trustworthy: positive control did not succeed (harness not shown capable of an authorized DCSync)"
	}
	return p.Negative.Verdict, p.Negative.Reason
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./internal/adefficacy/`
Expected: PASS (all three tasks).

- [ ] **Step 5: Add the lab-readiness section to the runbook**

Append a `## 10. DCSync control-efficacy (Phase 5 vertical)` section to `docs/operations/p5-ad-lab-operator-runbook.md` capturing spec §6: both principals run in the same build; DRSUAPI result is primary evidence and 4662 is corroboration; the negative PASS is accepted only when the positive PASSed; ambiguous/uncorrelated evidence → SKIPPED; a real `ControlDecisionSource` is required (none ships) and no live wiring is performed.

- [ ] **Step 6: Run the four related suites**

Run: `go test ./internal/adefficacy/ ./internal/controlval/ ./internal/adcontrolval/ ./internal/admatrix/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/adefficacy/pair.go orchestrator/internal/adefficacy/pair_test.go docs/operations/p5-ad-lab-operator-runbook.md
git commit -m "feat(adefficacy): trust-pairing gate + axis mapping + lab-readiness checklist

AcceptedNegativeVerdict downgrades a negative PASS to SKIPPED unless the
positive control cleanly PASSed; never mutates raw Validations, never upgrades.
Faithful mapping through adcontrolval. Runbook gains the DCSync-efficacy
readiness section (DRSUAPI primary / 4662 corroboration / same-build pair).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```
