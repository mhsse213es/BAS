# Control-Efficacy Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the lab-independent, fake-backed slice of a product-neutral control-efficacy validation layer: grade a deployed security control's observed response to an already-executed attack against a per-case expected outcome.

**Architecture:** A generic `internal/controlval` core (stdlib only; vendor- and AD-agnostic) owns the outcome/evidence/verdict model, the pure `Evaluate` function, and a `Provider` seam with a fake. A thin `internal/adcontrolval` bridge maps AD primitives to the generic model and surfaces results as an additive sixth axis on `admatrix.CapabilityState`. No real provider, no `dispatchRun` wiring, no live axis population.

**Tech Stack:** Go (module `github.com/audspect/bas`), standard `testing`. Tests run via `go test ./internal/<pkg>/` from the `orchestrator/` directory (Git Bash on the Windows build host).

**Spec:** `docs/superpowers/specs/2026-10-10-control-efficacy-validation-design.md`

**Execution:** Native/inline — decided (standing Inline Over Subagents preference). No execution-method question at handoff.

## Global Constraints

- `internal/controlval` imports **stdlib only** — no `adprimitive`, no `admatrix`, no vendor packages.
- Dependency direction is one-way: `adcontrolval → {controlval, adprimitive, admatrix}`; `admatrix` imports neither `controlval` nor `adcontrolval`; `controlval` imports none of them.
- The `admatrix` change is **additive only**: one new field on `CapabilityState`, one new type, one new summary count. It must not modify or collapse the five existing axes (`Modeled`, `ContentAvailability`/`ScenarioComposed`, `ExecutionValidation`, `DetectionValidation`) or their summary counts.
- Verdicts reuse the existing scoring taxonomy strings exactly: `PASS` / `FAIL` / `ERROR` / `SKIPPED`.
- Outcome alone never decides a verdict: `Evaluate` always compares observed-vs-expected.
- **Invariant A:** inferred-only evidence never establishes prevention (prevention expectation + `EvidenceInferred` → `SKIPPED`).
- **Invariant B:** a missing control-response stream (`obs == nil`) → `SKIPPED`; `Evaluate` never reads any other evidence stream.
- `Unknown` outcome, confidence below floor, or `ConfidenceNone` → `SKIPPED`; never a silent `PASS`.
- `Expectation.PolicyVerified` is honest: no code path in this slice sets it `true`.
- No real provider adapter, no live population of the axis (`CapabilityStates()` leaves `ControlEfficacy` at its zero value), no `dispatchRun` wiring.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Push after every commit.

## Review Focus

- **Inferred prevention slips through as PASS** (spec §5 Invariant A): a prevention expectation with inferred-only evidence must be `SKIPPED`, not `PASS` — pinned by `TestEvaluate_InferredPreventionIsSkipped` (Task 1).
- **Missing stream fabricated into a benign outcome** (spec §5 Invariant B): `obs == nil` must be `SKIPPED`, never defaulted to `allowed`/`PASS` — pinned by `TestEvaluate_MissingObservationIsSkipped` (Task 1).
- **`ConfidenceNone`/below-floor observed outcome promoted** (spec §5): must be `SKIPPED` — pinned by `TestEvaluate_BelowConfidenceFloorIsSkipped` and `TestEvaluate_NoneConfidenceIsSkipped` (Task 1).
- **The additive axis perturbs the five existing axes / summary counts** (spec §8, refinement 1): the new field defaults not-evaluated and the five summary counts are unchanged — pinned by `TestCapabilityStates_ControlEfficacyDefaultsNotEvaluated` and `TestSummarize_FiveExistingCountsUnchanged` (Task 3) and `TestAttach_LeavesFiveAxesUntouched` (Task 4).
- **`Action` correlation identifier drifts from the primitive id** (spec §8, §12.3): the bridge maps `primitive.ID` verbatim to `Action` — pinned by `TestActionForPrimitive_IsPrimitiveID` (Task 4).

**Spec §9 (control↔detection independence) coverage in this slice:** control-side independence is structural and tested — `Evaluate(exp, obs, opErr)` cannot reach the detection or execution streams (not in its signature), and `TestEvaluate_MissingObservationIsSkipped` proves it never fabricates a result from them. The full two-sided canonical case (a `Blocked` control PASS co-existing with a detection failure under one `CorrelationKey`) depends on both axes being live-populated, which is deferred/lab-gated here; it belongs to the live-wiring phase, not this slice. Executor: record this as a ruling if a reviewer flags §9 as uncovered.

---

### Task 1: `controlval` core — types + `Evaluate` truth table + invariants

**Files:**
- Create: `orchestrator/internal/controlval/controlval.go`
- Test: `orchestrator/internal/controlval/controlval_test.go`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces:
  - `type Outcome string` with consts `OutcomeAllowed="allowed"`, `OutcomeBlocked="blocked"`, `OutcomeMFAChallenged="mfa_challenged"`, `OutcomeTerminated="terminated"`, `OutcomeQuarantined="quarantined"`, `OutcomeUnknown="unknown"`; method `func (o Outcome) IsPrevention() bool`.
  - `type EvidenceKind string` with `EvidenceObserved="observed"`, `EvidenceInferred="inferred"`.
  - `type Confidence string` with `ConfidenceHigh="high"`, `ConfidenceMedium="medium"`, `ConfidenceLow="low"`, `ConfidenceNone="none"`.
  - `type TimeWindow struct { Start, End time.Time }`.
  - `type CorrelationKey struct { RunID, Target, Action string; Window TimeWindow }`.
  - `type Observation struct { Key CorrelationKey; Provider string; Outcome Outcome; EvidenceKind EvidenceKind; Confidence Confidence; Source string; ObservedAt time.Time; Detail string }`.
  - `type Expectation struct { Expected Outcome; PolicyBasis string; PolicyVerified bool; MinConfidence Confidence }`.
  - `type Verdict string` with `VerdictPass="PASS"`, `VerdictFail="FAIL"`, `VerdictError="ERROR"`, `VerdictSkipped="SKIPPED"`.
  - `type Validation struct { Key CorrelationKey; Expectation Expectation; Observation *Observation; Verdict Verdict; Reason string }`.
  - `func Evaluate(exp Expectation, obs *Observation, opErr error) Validation`.

- [ ] **Step 1: Write the failing tests (truth table + invariants)**

```go
package controlval

import (
	"errors"
	"testing"
)

func obs(o Outcome, ek EvidenceKind, c Confidence) *Observation {
	return &Observation{Provider: "fake", Outcome: o, EvidenceKind: ek, Confidence: c, Source: "test"}
}

func TestEvaluate_ObservedMatchExpectationPasses(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictPass {
		t.Fatalf("verdict = %q, want PASS (%s)", v.Verdict, v.Reason)
	}
}

func TestEvaluate_ExpectedBlockObservedAllowedIsGapFail(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeAllowed, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", v.Verdict)
	}
	if v.Reason == "" {
		t.Fatal("gap FAIL must carry a reason")
	}
}

func TestEvaluate_ExpectedAllowedObservedBlockedIsUnexpectedDenial(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeAllowed, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (unexpected denial)", v.Verdict)
	}
}

func TestEvaluate_ProviderErrorIsError(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked}, nil, errors.New("api down"))
	if v.Verdict != VerdictError {
		t.Fatalf("verdict = %q, want ERROR", v.Verdict)
	}
}

func TestEvaluate_MissingObservationIsSkipped(t *testing.T) { // Invariant B
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, nil, nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (missing stream must never be fabricated)", v.Verdict)
	}
}

func TestEvaluate_UnknownOutcomeIsSkipped(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceLow},
		obs(OutcomeUnknown, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", v.Verdict)
	}
}

func TestEvaluate_BelowConfidenceFloorIsSkipped(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceLow), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (below floor)", v.Verdict)
	}
}

func TestEvaluate_NoneConfidenceIsSkipped(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceNone},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceNone), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (none confidence is never sufficient)", v.Verdict)
	}
}

func TestEvaluate_InferredPreventionIsSkipped(t *testing.T) { // Invariant A
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceInferred, ConfidenceHigh), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (inferred cannot establish prevention)", v.Verdict)
	}
}

func TestEvaluate_InferredAllowedCanPass(t *testing.T) {
	// Allowed is NOT a prevention outcome, so inferred evidence may ground it.
	v := Evaluate(Expectation{Expected: OutcomeAllowed, MinConfidence: ConfidenceHigh},
		obs(OutcomeAllowed, EvidenceInferred, ConfidenceHigh), nil)
	if v.Verdict != VerdictPass {
		t.Fatalf("verdict = %q, want PASS", v.Verdict)
	}
}

func TestEvaluate_CarriesObservationKey(t *testing.T) {
	o := obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh)
	o.Key = CorrelationKey{RunID: "r1", Target: "dc01", Action: "dcsync"}
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, o, nil)
	if v.Key.Action != "dcsync" {
		t.Fatalf("key.Action = %q, want dcsync", v.Key.Action)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/controlval/`
Expected: FAIL — `undefined: Evaluate`, `undefined: Expectation`, etc. (compile failure because the package has no source file yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// Package controlval is a product-neutral, AD- and vendor-agnostic model for
// validating what a DEPLOYED security control did about an already-executed
// attack attempt. It grades an observed control response against a per-case
// expected outcome. It imports stdlib only.
//
// Lab-gated boundary: this package ships fake-backed only (see FakeProvider).
// A real provider adapter (Silverfort first) and any wiring into the execution
// path are deferred until a lab/client environment with the control inline is
// available -- no prevention claim may rest on mocks, configuration presence,
// or detection telemetry alone.
package controlval

import "time"

type Outcome string

const (
	OutcomeAllowed       Outcome = "allowed"
	OutcomeBlocked       Outcome = "blocked"
	OutcomeMFAChallenged Outcome = "mfa_challenged"
	OutcomeTerminated    Outcome = "terminated"
	OutcomeQuarantined   Outcome = "quarantined"
	OutcomeUnknown       Outcome = "unknown"
)

// IsPrevention reports whether the outcome asserts the control actively
// stopped or interrupted the attempt (as opposed to allowing it).
func (o Outcome) IsPrevention() bool {
	switch o {
	case OutcomeBlocked, OutcomeMFAChallenged, OutcomeTerminated, OutcomeQuarantined:
		return true
	default:
		return false
	}
}

type EvidenceKind string

const (
	EvidenceObserved EvidenceKind = "observed"
	EvidenceInferred EvidenceKind = "inferred"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default: // ConfidenceNone and "" both mean no confidence
		return 0
	}
}

type TimeWindow struct {
	Start time.Time
	End   time.Time
}

type CorrelationKey struct {
	RunID  string
	Target string
	Action string
	Window TimeWindow
}

type Observation struct {
	Key          CorrelationKey
	Provider     string
	Outcome      Outcome
	EvidenceKind EvidenceKind
	Confidence   Confidence
	Source       string
	ObservedAt   time.Time
	Detail       string
}

type Expectation struct {
	Expected       Outcome
	PolicyBasis    string
	PolicyVerified bool
	MinConfidence  Confidence
}

type Verdict string

const (
	VerdictPass    Verdict = "PASS"
	VerdictFail    Verdict = "FAIL"
	VerdictError   Verdict = "ERROR"
	VerdictSkipped Verdict = "SKIPPED"
)

type Validation struct {
	Key         CorrelationKey
	Expectation Expectation
	Observation *Observation
	Verdict     Verdict
	Reason      string
}

// Evaluate grades an observed control response against an expectation. It is
// pure over its inputs and reads NO other evidence stream. Outcome alone never
// decides the verdict. Invariant A: inferred-only evidence can never establish
// prevention. Invariant B: a nil observation is SKIPPED, never fabricated.
func Evaluate(exp Expectation, obs *Observation, opErr error) Validation {
	v := Validation{Expectation: exp, Observation: obs}
	if obs != nil {
		v.Key = obs.Key
	}
	switch {
	case opErr != nil:
		v.Verdict, v.Reason = VerdictError, "provider/validation operation failed: "+opErr.Error()
	case obs == nil:
		v.Verdict, v.Reason = VerdictSkipped, "control response not recorded"
	case obs.Outcome == OutcomeUnknown:
		v.Verdict, v.Reason = VerdictSkipped, "control outcome unknown"
	case confidenceRank(obs.Confidence) == 0 || confidenceRank(obs.Confidence) < confidenceRank(exp.MinConfidence):
		v.Verdict, v.Reason = VerdictSkipped, "below required confidence threshold"
	case exp.Expected.IsPrevention() && obs.EvidenceKind == EvidenceInferred:
		v.Verdict, v.Reason = VerdictSkipped, "inferred-only evidence cannot establish prevention"
	case obs.Outcome == exp.Expected:
		v.Verdict, v.Reason = VerdictPass, "observed outcome matches expectation"
	case exp.Expected.IsPrevention() && obs.Outcome == OutcomeAllowed:
		v.Verdict, v.Reason = VerdictFail, "expected prevention, observed allowed (control gap)"
	case exp.Expected == OutcomeAllowed && obs.Outcome.IsPrevention():
		v.Verdict, v.Reason = VerdictFail, "unexpected denial"
	default:
		v.Verdict, v.Reason = VerdictFail, "observed outcome contradicts expectation"
	}
	return v
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/controlval/`
Expected: PASS (all cases).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/controlval/controlval.go orchestrator/internal/controlval/controlval_test.go
git commit -m "feat(controlval): core outcome/evidence/verdict model + Evaluate truth table

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

### Task 2: `controlval` Provider seam + `FakeProvider`

**Files:**
- Create: `orchestrator/internal/controlval/provider.go`
- Test: `orchestrator/internal/controlval/provider_test.go`

**Interfaces:**
- Consumes: `Observation`, `CorrelationKey`, `Outcome`, `OutcomeUnknown`, `EvidenceKind`, `Confidence` (Task 1).
- Produces:
  - `type Provider interface { Name() string; Observe(ctx context.Context, key CorrelationKey) (Observation, error) }`.
  - `type FakeProvider struct { ProviderName string; Obs map[string]Observation; Err map[string]error }`.
  - `func (f *FakeProvider) Name() string` and `func (f *FakeProvider) Observe(ctx context.Context, key CorrelationKey) (Observation, error)`.

- [ ] **Step 1: Write the failing tests**

```go
package controlval

import (
	"context"
	"errors"
	"testing"
)

func TestFakeProvider_ReturnsCannedObservationWithKey(t *testing.T) {
	f := &FakeProvider{
		ProviderName: "fake",
		Obs: map[string]Observation{
			"dcsync": {Outcome: OutcomeBlocked, EvidenceKind: EvidenceObserved, Confidence: ConfidenceHigh, Source: "fake-api"},
		},
	}
	key := CorrelationKey{RunID: "r1", Target: "dc01", Action: "dcsync"}
	got, err := f.Observe(context.Background(), key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Outcome != OutcomeBlocked {
		t.Fatalf("outcome = %q, want blocked", got.Outcome)
	}
	if got.Key.Action != "dcsync" {
		t.Fatalf("Observe must stamp the queried key; got Action %q", got.Key.Action)
	}
	if got.Provider != "fake" {
		t.Fatalf("provider = %q, want fake", got.Provider)
	}
}

func TestFakeProvider_UnknownActionReturnsUnknownNotError(t *testing.T) {
	f := &FakeProvider{ProviderName: "fake"}
	got, err := f.Observe(context.Background(), CorrelationKey{Action: "never-seen"})
	if err != nil {
		t.Fatalf("missing correlation must NOT be an error: %v", err)
	}
	if got.Outcome != OutcomeUnknown {
		t.Fatalf("outcome = %q, want unknown", got.Outcome)
	}
}

func TestFakeProvider_ErrorPath(t *testing.T) {
	f := &FakeProvider{ProviderName: "fake", Err: map[string]error{"boom": errors.New("api down")}}
	if _, err := f.Observe(context.Background(), CorrelationKey{Action: "boom"}); err == nil {
		t.Fatal("expected a technical error for the configured action")
	}
}

func TestFakeProvider_SatisfiesProviderInterface(t *testing.T) {
	var _ Provider = (*FakeProvider)(nil)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/controlval/ -run TestFakeProvider`
Expected: FAIL — `undefined: FakeProvider`, `undefined: Provider`.

- [ ] **Step 3: Write the minimal implementation**

```go
package controlval

import "context"

// Provider observes a DEPLOYED security control's response to an already-
// executed attack attempt. It does NOT execute the attack. When it cannot
// correlate a response it returns an Outcome=unknown observation (not an
// error); error is reserved for a technical failure of the observation itself.
type Provider interface {
	Name() string
	Observe(ctx context.Context, key CorrelationKey) (Observation, error)
}

// FakeProvider is the only provider in this slice. It returns canned
// observations by Action, or a configured error, or an Unknown observation
// when the Action is not configured. Real adapters are deferred (spec §7).
type FakeProvider struct {
	ProviderName string
	Obs          map[string]Observation
	Err          map[string]error
}

func (f *FakeProvider) Name() string { return f.ProviderName }

func (f *FakeProvider) Observe(_ context.Context, key CorrelationKey) (Observation, error) {
	if err, ok := f.Err[key.Action]; ok {
		return Observation{}, err
	}
	if o, ok := f.Obs[key.Action]; ok {
		o.Key = key
		if o.Provider == "" {
			o.Provider = f.ProviderName
		}
		return o, nil
	}
	return Observation{Key: key, Provider: f.ProviderName, Outcome: OutcomeUnknown,
		Confidence: ConfidenceNone, Detail: "no correlated control response"}, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/controlval/`
Expected: PASS (Task 1 + Task 2 tests).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/controlval/provider.go orchestrator/internal/controlval/provider_test.go
git commit -m "feat(controlval): Provider seam + fake-backed FakeProvider

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

### Task 3: `admatrix` additive sixth axis + `ControlValidated` summary count

**Files:**
- Modify: `orchestrator/internal/admatrix/capability_state.go` (add type + field near the existing axis fields ~line 92; add count to `CapabilityStateSummary` ~line 127 and to `SummarizeCapabilityStates` ~line 437)
- Test: `orchestrator/internal/admatrix/control_efficacy_test.go` (create)

**Interfaces:**
- Consumes: existing `CapabilityState`, `CapabilityStateSummary`, `CapabilityStates()`, `SummarizeCapabilityStates()` (admatrix).
- Produces:
  - `type ControlEfficacyState struct { Evaluated bool; Verdict, Provider, Observed, Expected, EvidenceKind, Confidence, Reason string }` with json tags `evaluated`, `verdict,omitempty`, `provider,omitempty`, `observedOutcome,omitempty`, `expectedOutcome,omitempty`, `evidenceKind,omitempty`, `confidence,omitempty`, `reason,omitempty`.
  - New field `CapabilityState.ControlEfficacy ControlEfficacyState` json tag `controlEfficacy`.
  - New field `CapabilityStateSummary.ControlValidated int` json tag `controlValidated`.

- [ ] **Step 1: Write the failing tests**

```go
package admatrix

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilityStates_ControlEfficacyDefaultsNotEvaluated(t *testing.T) {
	for _, cs := range CapabilityStates() {
		if cs.ControlEfficacy.Evaluated {
			t.Fatalf("%s: ControlEfficacy must default to not-evaluated in this slice", cs.PrimitiveID)
		}
		if cs.ControlEfficacy.Verdict != "" {
			t.Fatalf("%s: not-evaluated axis must carry no verdict", cs.PrimitiveID)
		}
	}
}

func TestControlEfficacy_JSONKeyIsCamelCase(t *testing.T) {
	b, err := json.Marshal(CapabilityState{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"controlEfficacy"`) {
		t.Fatalf("expected camelCase controlEfficacy key, got: %s", b)
	}
	if strings.Contains(string(b), `"ControlEfficacy"`) {
		t.Fatal("PascalCase key leaked into JSON")
	}
}

func TestSummarize_ControlValidatedIsZeroThisSlice(t *testing.T) {
	if got := SummarizeCapabilityStates().ControlValidated; got != 0 {
		t.Fatalf("ControlValidated = %d, want 0 (nothing populates the axis live yet)", got)
	}
}

func TestSummarize_FiveExistingCountsUnchanged(t *testing.T) {
	// The additive axis must not perturb the five existing rollups. The five
	// counts must stay internally consistent: Total > 0 and each count <= Total.
	s := SummarizeCapabilityStates()
	if s.Total == 0 {
		t.Fatal("expected a non-empty capability set")
	}
	for name, n := range map[string]int{
		"Modeled": s.Modeled, "ScenarioComposed": s.ScenarioComposed,
		"Executed": s.Executed, "DetectionValidated": s.DetectionValidated,
	} {
		if n > s.Total {
			t.Fatalf("%s count %d exceeds Total %d", name, n, s.Total)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/admatrix/ -run 'ControlEfficacy|ControlValidated|FiveExisting'`
Expected: FAIL — `cs.ControlEfficacy undefined`, `s.ControlValidated undefined`.

- [ ] **Step 3: Write the minimal implementation**

Add the type and field to `capability_state.go`. Insert the field immediately after the `DetectionValidation` field (~line 93), and the type near the other axis types:

```go
	ExecutionValidation ExecutionValidation `json:"executionValidation"`
	DetectionValidation DetectionValidation `json:"detectionValidation"`

	// ControlEfficacy is the sixth, INDEPENDENT axis: whether a DEPLOYED
	// security control produced its expected response to this capability.
	// Zero value = not evaluated. It never modifies or collapses the five
	// existing axes, and it is independent of DetectionValidation -- a blocked
	// attempt with no SIEM alert may be a PASS here and a detection failure.
	// Populated only via the adcontrolval bridge from real provider
	// observations; live wiring is DEFERRED (lab-gated), so CapabilityStates()
	// leaves this at its zero value in this slice.
	ControlEfficacy ControlEfficacyState `json:"controlEfficacy"`
```

```go
// ControlEfficacyState is the admatrix-local view of a control-efficacy
// result. It is filled by the adcontrolval bridge; admatrix imports no
// controlval or vendor code.
type ControlEfficacyState struct {
	Evaluated    bool   `json:"evaluated"`
	Verdict      string `json:"verdict,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Observed     string `json:"observedOutcome,omitempty"`
	Expected     string `json:"expectedOutcome,omitempty"`
	EvidenceKind string `json:"evidenceKind,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
	Reason       string `json:"reason,omitempty"`
}
```

Add the count to `CapabilityStateSummary` (after `DetectionValidated`):

```go
	DetectionValidated int `json:"detectionValidated"`
	ControlValidated   int `json:"controlValidated"`
```

Add the rollup line inside the loop in `SummarizeCapabilityStates`, after the `DetectionValidation` check:

```go
		if cs.ControlEfficacy.Verdict == "PASS" {
			s.ControlValidated++
		}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/admatrix/`
Expected: PASS (new tests + existing admatrix suite — the additive field must not break any existing test).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/admatrix/capability_state.go orchestrator/internal/admatrix/control_efficacy_test.go
git commit -m "feat(admatrix): additive sixth control-efficacy axis + ControlValidated count

Zero-valued (not-evaluated) in this slice; five existing axes untouched.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

### Task 4: `adcontrolval` bridge — primitive→action, key, mapping, `Attach`

**Files:**
- Create: `orchestrator/internal/adcontrolval/bridge.go`
- Test: `orchestrator/internal/adcontrolval/bridge_test.go`

**Interfaces:**
- Consumes: `controlval.{Validation, Observation, CorrelationKey, TimeWindow, Outcome, EvidenceKind, Confidence, Verdict, Expectation}` (Tasks 1–2); `adprimitive.Primitive` with field `ID string` (`adprimitive/types.go:185`); `admatrix.{CapabilityState, ControlEfficacyState}` (Task 3).
- Produces:
  - `func ActionForPrimitive(p adprimitive.Primitive) string` (returns `p.ID` verbatim).
  - `func CorrelationKeyFor(p adprimitive.Primitive, runID, target string, window controlval.TimeWindow) controlval.CorrelationKey`.
  - `func ToEfficacyState(v controlval.Validation) admatrix.ControlEfficacyState`.
  - `func Attach(cs admatrix.CapabilityState, v controlval.Validation) admatrix.CapabilityState`.

- [ ] **Step 1: Write the failing tests**

```go
package adcontrolval

import (
	"testing"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
)

func TestActionForPrimitive_IsPrimitiveID(t *testing.T) {
	if got := ActionForPrimitive(adprimitive.Primitive{ID: "dcsync"}); got != "dcsync" {
		t.Fatalf("action = %q, want dcsync (verbatim primitive id)", got)
	}
}

func TestCorrelationKeyFor_CarriesRunTargetAction(t *testing.T) {
	k := CorrelationKeyFor(adprimitive.Primitive{ID: "kerberoast"}, "run1", "dc01", controlval.TimeWindow{})
	if k.RunID != "run1" || k.Target != "dc01" || k.Action != "kerberoast" {
		t.Fatalf("key = %+v, want run1/dc01/kerberoast", k)
	}
}

func TestToEfficacyState_MapsVerdictAndObservation(t *testing.T) {
	v := controlval.Validation{
		Expectation: controlval.Expectation{Expected: controlval.OutcomeBlocked},
		Observation: &controlval.Observation{Provider: "silverfort", Outcome: controlval.OutcomeBlocked,
			EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
		Verdict: controlval.VerdictPass,
		Reason:  "observed outcome matches expectation",
	}
	s := ToEfficacyState(v)
	if !s.Evaluated || s.Verdict != "PASS" || s.Provider != "silverfort" ||
		s.Observed != "blocked" || s.Expected != "blocked" ||
		s.EvidenceKind != "observed" || s.Confidence != "high" || s.Reason == "" {
		t.Fatalf("mapping wrong: %+v", s)
	}
}

func TestToEfficacyState_NilObservationStillEvaluatedWithVerdict(t *testing.T) {
	v := controlval.Validation{
		Expectation: controlval.Expectation{Expected: controlval.OutcomeBlocked},
		Verdict:     controlval.VerdictSkipped, Reason: "control response not recorded",
	}
	s := ToEfficacyState(v)
	if !s.Evaluated || s.Verdict != "SKIPPED" || s.Provider != "" || s.Observed != "" {
		t.Fatalf("nil-observation mapping wrong: %+v", s)
	}
}

func TestAttach_LeavesFiveAxesUntouched(t *testing.T) {
	cs := admatrix.CapabilityState{
		PrimitiveID:         "dcsync",
		Modeled:             true,
		ScenarioComposed:    true,
		ExecutionValidation: admatrix.ExecCompleted,
		DetectionValidation: admatrix.DetTelemetryObserved,
	}
	out := Attach(cs, controlval.Validation{Verdict: controlval.VerdictPass})
	if out.Modeled != cs.Modeled || out.ScenarioComposed != cs.ScenarioComposed ||
		out.ExecutionValidation != cs.ExecutionValidation || out.DetectionValidation != cs.DetectionValidation {
		t.Fatal("Attach must not modify the five existing axes")
	}
	if !out.ControlEfficacy.Evaluated || out.ControlEfficacy.Verdict != "PASS" {
		t.Fatalf("Attach must set the sixth axis: %+v", out.ControlEfficacy)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/adcontrolval/`
Expected: FAIL — `undefined: ActionForPrimitive` etc. (no source file yet).

> If `admatrix.ExecCompleted`, `admatrix.ExecPostconditionVerified`, or `admatrix.DetTelemetryObserved` are not the exact exported identifiers (confirm against `capability_state.go` — `SummarizeCapabilityStates` at line 447/450 uses `ExecCompleted`, `ExecPostconditionVerified`, `DetTelemetryObserved`), substitute the real constant names in the test. This is a ruling to record, not a plan break.

- [ ] **Step 3: Write the minimal implementation**

```go
// Package adcontrolval bridges AD primitives into the product-neutral
// controlval model and surfaces the result as admatrix's sixth
// (control-efficacy) axis. It depends one-way on controlval, adprimitive and
// admatrix; none of those gains AD- or controlval-awareness in return.
//
// Live population of the axis from real provider observations is DEFERRED and
// lab-gated (spec §10): this package ships the mapping and is exercised by
// tests, but nothing wires it into CapabilityStates() or the execution path.
package adcontrolval

import (
	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
)

// ActionForPrimitive maps a primitive to the opaque controlval Action id. The
// mapping is the primitive id verbatim so the correlation key is stable.
func ActionForPrimitive(p adprimitive.Primitive) string { return p.ID }

// CorrelationKeyFor builds the controlval key for checking p's control response
// in a given run/target/time window. p carries no run context, so the caller
// supplies it (mirrors addetect.VerifyRequestFor).
func CorrelationKeyFor(p adprimitive.Primitive, runID, target string, window controlval.TimeWindow) controlval.CorrelationKey {
	return controlval.CorrelationKey{RunID: runID, Target: target, Action: ActionForPrimitive(p), Window: window}
}

// ToEfficacyState maps a controlval.Validation to the admatrix-local axis view.
func ToEfficacyState(v controlval.Validation) admatrix.ControlEfficacyState {
	s := admatrix.ControlEfficacyState{
		Evaluated: true,
		Verdict:   string(v.Verdict),
		Expected:  string(v.Expectation.Expected),
		Reason:    v.Reason,
	}
	if v.Observation != nil {
		s.Provider = v.Observation.Provider
		s.Observed = string(v.Observation.Outcome)
		s.EvidenceKind = string(v.Observation.EvidenceKind)
		s.Confidence = string(v.Observation.Confidence)
	}
	return s
}

// Attach returns a copy of cs with its control-efficacy axis set from v. It
// never touches the five existing axes.
func Attach(cs admatrix.CapabilityState, v controlval.Validation) admatrix.CapabilityState {
	cs.ControlEfficacy = ToEfficacyState(v)
	return cs
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/adcontrolval/`
Expected: PASS.

- [ ] **Step 5: Run the full AD + matrix suites to confirm no regression**

Run: `go test ./internal/controlval/ ./internal/adcontrolval/ ./internal/admatrix/ ./internal/adprimitive/`
Expected: PASS (all four packages).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adcontrolval/
git commit -m "feat(adcontrolval): AD bridge mapping primitives to the control-efficacy axis

Lab-gated: mapping only, no live CapabilityStates() wiring. Attach leaves the
five existing axes untouched.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```
