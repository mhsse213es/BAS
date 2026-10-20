# Ransomware Evidence Engine — T1490 Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first real vertical of the Ransomware Mastery initiative — three independently-verified capability dimensions (Prevention, Recovery, Detection) for T1490 (Inhibit System Recovery), proving the architecture works before any other capability or technique is added.

**Architecture:** One additive field on the existing canonical `controlval.Validation` (`SkipReason`), plus one new, self-contained package `internal/rwevidence` that adapts `controlval` for Prevention, defines its own verification contract for Recovery, and thinly wraps existing detection-profile output for Detection. No execution, no real observers, no scenario-content changes.

**Tech Stack:** Go (stdlib only + existing internal packages `controlval`, `adprimitive`). TDD throughout, matching this session's established pattern for `controlval`/`adcontrolval`/`latmove`/`latdetect`.

**Spec:** `docs/superpowers/specs/2026-10-10-rwevidence-t1490-vertical-design.md`

**Execution: already decided — native/inline** (standing "Inline Over Subagents" preference; Sonnet only). Each task below is implemented directly in this session, RED→GREEN→full-package-verify→commit→push, with one final self-review pass across the whole branch at the end — no per-task subagent dispatch.

## Global Constraints

- No second verdict taxonomy. Every `Verdict` value is one of `controlval.VerdictPass`/`VerdictFail`/`VerdictError`/`VerdictSkipped` — nothing else is ever assigned to a `CapabilityResult.Verdict`.
- `SkipReason` must be empty for `PASS`, `FAIL`, and `ERROR`; `SKIPPED` must always carry one of `SkipInsufficientEvidence`/`SkipNotApplicable`/`SkipNotTested` — never empty, never a 4th value.
- `controlval.Validation` and `controlval.Evaluate` stay generic. No T1490-specific type, constant, or branch is ever added to the `controlval` package — all of that lives in `rwevidence`.
- This slice executes nothing and adds no new safety gate. The existing scenario-engine gate (`BAS_CONFIRM_VSS_DELETE`) is untouched and remains the only thing that governs real VSS-deletion execution.
- Fake-backed only. No real `RecoveryObserver`, no real detection-profile wiring, no real `controlval.Provider` — every external boundary in this slice ships exactly one fake implementation, same discipline as `controlval.FakeProvider`/`latmove.FakeObserver`.
- A verdict of `PASS`/`FAIL` on one `Capability` must never be derived from, or silently coerced to match, another `Capability`'s verdict for the same attempt.

## Review Focus

- Recovery's and Detection's own `PASS`/`FAIL` outputs must never carry a non-empty `SkipReason` — the global invariant must hold locally in `rwevidence`'s own code, not just in `controlval.Evaluate`. (Task 4, Task 5)
- A `RecoveryObserver` operational error must take precedence over any `SurvivalResult` it also returns — same error-precedence rule `controlval.Evaluate` already enforces for `opErr`. Without this, a WMI-unreachable failure could silently read as `SurvivalIndeterminate` instead of a visible `ERROR`. (Task 4)
- Detection-profile corroboration riding along in a Recovery `CapabilityResult.Reason` must never change the `Verdict` by itself — a `Confirmed` survival stays `PASS` whether or not the EDR also alerted. (Task 4)
- Every Recovery `CapabilityResult.Reason` must explicitly scope the claim to the targeted shadow copies/backup catalog for this one attempt — never phrased in a way a reader could generalize into "backup systems are recoverable." (Task 4)
- Cross-capability independence under a realistic mixed outcome: Prevention `FAIL` (the destructive command got through) and Recovery `PASS` (the targeted data survived anyway, e.g. a backup-side control caught what the endpoint missed) must coexist for the same attempt without either result changing the other. (Task 5)

---

### Task 1: `controlval.SkipReason`

**Files:**
- Modify: `orchestrator/internal/controlval/controlval.go:123-184` (add `SkipReason` type + constants, add field to `Validation`, tag the 4 existing `VerdictSkipped` branches in `Evaluate`)
- Test: `orchestrator/internal/controlval/controlval_test.go` (add 2 new invariant tests)

**Interfaces:**
- Produces: `controlval.SkipReason` (string type), constants `SkipInsufficientEvidence`, `SkipNotApplicable`, `SkipNotTested`; `Validation.SkipReason SkipReason` field (JSON tag `skipReason,omitempty`).

**Context verified against current source (do not re-derive — these are the exact 4 branches in `Evaluate` today, lines 163-174):**
```go
switch {
case opErr != nil:
    v.Verdict, v.Reason = VerdictError, "provider/validation operation failed: "+opErr.Error()
case obs == nil:
    v.Verdict, v.Reason = VerdictSkipped, "control response not recorded"
case obs.Outcome == OutcomeUnknown:
    v.Verdict, v.Reason = VerdictSkipped, "control outcome unknown"
case confidenceRank(obs.Confidence) == 0 || confidenceRank(obs.Confidence) < confidenceRank(effectiveFloor(exp.MinConfidence)):
    v.Verdict, v.Reason = VerdictSkipped, "below required confidence threshold"
case exp.Expected.IsPrevention() && obs.EvidenceKind == EvidenceInferred:
    v.Verdict, v.Reason = VerdictSkipped, "inferred-only evidence cannot establish prevention"
case obs.Outcome == exp.Expected:
    v.Verdict, v.Reason = VerdictPass, "observed outcome matches expectation"
// ...FAIL branches unchanged
}
```
Only `obs == nil` is genuinely "no evaluation was ever attempted" → `SkipNotTested`. The other three branches all have *some* evidence that simply doesn't clear the bar → all three get `SkipInsufficientEvidence`.

**Verified fact (do not redo as a task):** no existing test in `controlval`, `adcontrolval`, `latmove`, or `adefficacy` performs full-struct equality against `Evaluate`'s output — every existing assertion checks `.Verdict` (or, for `adefficacy.Pair`/`latmove`'s equivalent, a bare `controlval.Verdict` return value) as an individual field. Confirmed via `grep -n VerdictSkipped` across `orchestrator/internal`. Adding `SkipReason` is therefore purely additive: **no existing test anywhere needs modification.** This corrects the spec's §3/§8 "migration cost" language, which overstated this risk before the actual assertion style was checked against source.

- [ ] **Step 1: Write the two failing tests**

Append to `orchestrator/internal/controlval/controlval_test.go` (the file already imports `"errors"` and has the `obs(o Outcome, ek EvidenceKind, c Confidence) *Observation` helper at line 8 — reuse it, do not redefine):

```go
func TestEvaluate_SkippedAlwaysHasRecognizedReason(t *testing.T) {
	recognized := map[SkipReason]bool{
		SkipInsufficientEvidence: true,
		SkipNotApplicable:        true,
		SkipNotTested:            true,
	}
	cases := []struct {
		name string
		exp  Expectation
		obs  *Observation
	}{
		{"nil observation", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, nil},
		{"unknown outcome", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceLow}, obs(OutcomeUnknown, EvidenceObserved, ConfidenceHigh)},
		{"below confidence floor", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceObserved, ConfidenceLow)},
		{"inferred cannot establish prevention", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceInferred, ConfidenceHigh)},
	}
	for _, c := range cases {
		v := Evaluate(c.exp, c.obs, nil)
		if v.Verdict != VerdictSkipped {
			t.Fatalf("%s: verdict = %q, want SKIPPED", c.name, v.Verdict)
		}
		if !recognized[v.SkipReason] {
			t.Fatalf("%s: SkipReason = %q, want one of the 3 recognized reasons", c.name, v.SkipReason)
		}
	}
}

func TestEvaluate_NonSkippedNeverHasSkipReason(t *testing.T) {
	cases := []struct {
		name string
		exp  Expectation
		obs  *Observation
		err  error
	}{
		{"error", Expectation{Expected: OutcomeBlocked}, nil, errors.New("api down")},
		{"pass", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil},
		{"fail", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeAllowed, EvidenceObserved, ConfidenceHigh), nil},
	}
	for _, c := range cases {
		v := Evaluate(c.exp, c.obs, c.err)
		if v.Verdict == VerdictSkipped {
			t.Fatalf("%s: unexpectedly SKIPPED", c.name)
		}
		if v.SkipReason != "" {
			t.Fatalf("%s: verdict %q has non-empty SkipReason %q, want empty", c.name, v.Verdict, v.SkipReason)
		}
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd orchestrator && go test ./internal/controlval/ -run 'TestEvaluate_SkippedAlwaysHasRecognizedReason|TestEvaluate_NonSkippedNeverHasSkipReason' -v`
Expected: build failure — `undefined: SkipReason`, `undefined: SkipInsufficientEvidence` (etc.), `v.SkipReason` field undefined.

- [ ] **Step 3: Implement**

In `controlval.go`, immediately after the `Verdict` const block (after line 131):

```go
// SkipReason explains WHY a SKIPPED verdict occurred -- canonical, shared
// across every consumer of this taxonomy. It always rides on top of
// VerdictSkipped; it is never a verdict value on its own, and it never
// fragments the taxonomy into a second one.
type SkipReason string

const (
	SkipInsufficientEvidence SkipReason = "insufficient_evidence" // evidence exists but does not establish the outcome
	SkipNotApplicable        SkipReason = "not_applicable"        // the capability genuinely does not apply here -- Evaluate never sets this itself; only a caller does, for an attempt it never ran
	SkipNotTested            SkipReason = "not_tested"            // no evaluation was ever attempted
)
```

Add the field to `Validation` (line 136-142):

```go
type Validation struct {
	Key         CorrelationKey
	Expectation Expectation
	Observation *Observation
	Verdict     Verdict
	SkipReason  SkipReason `json:"skipReason,omitempty"`
	Reason      string
}
```

Tag the 4 branches in `Evaluate` (lines 163-174):

```go
	switch {
	case opErr != nil:
		v.Verdict, v.Reason = VerdictError, "provider/validation operation failed: "+opErr.Error()
	case obs == nil:
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipNotTested, "control response not recorded"
	case obs.Outcome == OutcomeUnknown:
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipInsufficientEvidence, "control outcome unknown"
	case confidenceRank(obs.Confidence) == 0 || confidenceRank(obs.Confidence) < confidenceRank(effectiveFloor(exp.MinConfidence)):
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipInsufficientEvidence, "below required confidence threshold"
	case exp.Expected.IsPrevention() && obs.EvidenceKind == EvidenceInferred:
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipInsufficientEvidence, "inferred-only evidence cannot establish prevention"
	case obs.Outcome == exp.Expected:
		v.Verdict, v.Reason = VerdictPass, "observed outcome matches expectation"
	case exp.Expected.IsPrevention() && obs.Outcome == OutcomeAllowed:
		v.Verdict, v.Reason = VerdictFail, "expected prevention, observed allowed (control gap)"
	case exp.Expected == OutcomeAllowed && obs.Outcome.IsPrevention():
		v.Verdict, v.Reason = VerdictFail, "unexpected denial"
	default:
		v.Verdict, v.Reason = VerdictFail, "observed outcome contradicts expectation"
	}
```

- [ ] **Step 4: Run to verify GREEN, then verify zero breakage across all 4 consuming packages**

Run: `cd orchestrator && go test ./internal/controlval/ -v`
Expected: PASS, including the 2 new tests.

Run: `cd orchestrator && go test ./internal/controlval/ ./internal/adcontrolval/ ./internal/latmove/ ./internal/adefficacy/`
Expected: `ok` for all 4 — confirms the additive field broke nothing, proving the "no migration needed" finding from Step 0's context note.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/controlval/controlval.go orchestrator/internal/controlval/controlval_test.go
git commit -m "feat(controlval): add canonical SkipReason to Validation

insufficient_evidence/not_applicable/not_tested distinguish WHY a SKIPPED
verdict occurred, without introducing a second verdict taxonomy. Evaluate's
4 existing Skipped branches tagged: only obs==nil is genuinely not_tested;
the other 3 (unknown outcome, below-confidence-floor, inferred-only) all
have some evidence that doesn't clear the bar -> insufficient_evidence.
Purely additive -- verified zero breakage across controlval/adcontrolval/
latmove/adefficacy, none of which asserts full Validation equality."
git push
```

---

### Task 2: `rwevidence` shared types + `VSSInhibition` technique

**Files:**
- Create: `orchestrator/internal/rwevidence/types.go`
- Create: `orchestrator/internal/rwevidence/technique.go`
- Test: `orchestrator/internal/rwevidence/technique_test.go`

**Interfaces:**
- Consumes: `controlval.Verdict`, `controlval.SkipReason`, `controlval.CorrelationKey` (Task 1); `adprimitive.RiskClass`, `adprimitive.RiskDestructive` (existing, verified at `orchestrator/internal/adprimitive/types.go:146-152` — a 3-value tier: `RiskNonDestructive`/`RiskPotentiallyDestructive`/`RiskDestructive`).
- Produces: `Capability` + 5 constants; `CapabilityResult{Capability, TechniqueID, Verdict, SkipReason, Reason, Provenance}`; `AttemptKey{RunID, TechniqueID}`; `Technique{ID, Name, MitreID, RiskClass}`; `VSSInhibition() Technique`. Every later task in this plan consumes these exact names and fields.

**Note on `RiskDestructive`:** verified via `grep` that no primitive in `adprimitive`'s catalog uses this value yet — `VSSInhibition` is its first real consumer. This is deliberate, not a placeholder: a created service or scheduled task (both `RiskPotentiallyDestructive` in `latmove`) can be deleted to undo it; a genuinely deleted shadow copy cannot be recreated. That irreversibility is exactly what the 3rd tier exists for.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/rwevidence/technique_test.go`:

```go
package rwevidence

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestVSSInhibition_StableIdentity(t *testing.T) {
	tech := VSSInhibition()
	if tech.ID != "vss-inhibition" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1490" {
		t.Fatalf("mitreID = %q, want T1490", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskDestructive {
		t.Fatalf("riskClass = %q, want destructive (a deleted shadow copy cannot be recreated)", tech.RiskClass)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: build failure — package `rwevidence` does not exist / `undefined: VSSInhibition`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/rwevidence/types.go`:

```go
// Package rwevidence is a dedicated, capability-specific evidence engine
// for ransomware techniques -- the ransomware equivalent of
// adprimitive/admatrix/controlval (AD) and latmove/latdetect (lateral
// movement). It proves whether a deployed control actually prevented,
// detected, contained, recovered from, or protected data against a
// ransomware behavior, as independently-verified evidence rather than a
// scenario step merely running.
//
// This first slice covers exactly one technique (T1490, Inhibit System
// Recovery) and three of the five capability dimensions (Prevention,
// Recovery, Detection). Containment and DataProtection, every real
// observer, and any scoring/weighting UI are explicitly deferred.
package rwevidence

import "github.com/audspect/bas/internal/controlval"

// Capability names one of the five ransomware-mastery reporting dimensions.
// These are reporting categories, not independent execution engines: one
// technique can and does produce several independently-verified
// CapabilityResults, one per applicable dimension -- never inferred from
// each other.
type Capability string

const (
	CapabilityPrevention     Capability = "prevention"
	CapabilityDetection      Capability = "detection"
	CapabilityContainment    Capability = "containment"
	CapabilityRecovery       Capability = "recovery"
	CapabilityDataProtection Capability = "data_protection"
)

// CapabilityResult is one independently-verified claim about one capability
// dimension for one technique attempt.
type CapabilityResult struct {
	Capability  Capability
	TechniqueID string
	Verdict     controlval.Verdict
	SkipReason  controlval.SkipReason
	Reason      string
	Provenance  controlval.CorrelationKey
}

// AttemptKey identifies one technique attempt, for correlating independent
// observers (Recovery, ...) against the same event.
type AttemptKey struct {
	RunID       string
	TechniqueID string
}
```

Create `orchestrator/internal/rwevidence/technique.go`:

```go
package rwevidence

import "github.com/audspect/bas/internal/adprimitive"

// Technique identifies one ransomware technique this package has evidence
// support for. RiskClass is informational only here -- this package
// executes nothing and gates nothing; the existing scenario engine's own
// safety gate (BAS_CONFIRM_VSS_DELETE) is what actually governs execution.
type Technique struct {
	ID        string
	Name      string
	MitreID   string
	RiskClass adprimitive.RiskClass
}

// VSSInhibition is the first technique this package supports: deletion of
// shadow copies / backup catalog entries (T1490, Inhibit System Recovery).
func VSSInhibition() Technique {
	return Technique{
		ID:        "vss-inhibition",
		Name:      "Inhibit System Recovery (VSS/Backup Catalog)",
		MitreID:   "T1490",
		RiskClass: adprimitive.RiskDestructive,
	}
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/rwevidence/types.go orchestrator/internal/rwevidence/technique.go orchestrator/internal/rwevidence/technique_test.go
git commit -m "feat(rwevidence): shared Capability/CapabilityResult contract + VSSInhibition technique

New package, ransomware equivalent of adprimitive/admatrix/controlval and
latmove/latdetect. Capability is a reporting dimension, not an execution
engine -- CapabilityResult is one independently-verified claim per
dimension per attempt. VSSInhibition (T1490) is RiskDestructive, the
first real consumer of that tier: unlike a created service/task, a
genuinely deleted shadow copy cannot be recreated."
git push
```

---

### Task 3: Prevention — adapter to `controlval`

**Files:**
- Create: `orchestrator/internal/rwevidence/prevention.go`
- Test: `orchestrator/internal/rwevidence/prevention_test.go`

**Interfaces:**
- Consumes: `Technique`, `CapabilityResult`, `CapabilityPrevention` (Task 2); `controlval.Expectation`, `controlval.Evaluate`, `controlval.FakeProvider`, `controlval.Observation`, `controlval.CorrelationKey`, `controlval.OutcomeBlocked`/`OutcomeAllowed`, `controlval.ConfidenceHigh`, `controlval.EvidenceObserved` (existing).
- Produces: `PreventionExpectationFor(tech Technique) controlval.Expectation`; `PreventionFromValidation(tech Technique, v controlval.Validation) CapabilityResult`. Task 5's end-to-end test calls both by these exact names.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwevidence/prevention_test.go`:

```go
package rwevidence

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestPreventionExpectationFor_ExpectsBlocked(t *testing.T) {
	exp := PreventionExpectationFor(VSSInhibition())
	if exp.Expected != controlval.OutcomeBlocked {
		t.Fatalf("expected = %q, want blocked", exp.Expected)
	}
}

func TestPreventionFromValidation_TranslatesVerbatim(t *testing.T) {
	tech := VSSInhibition()
	key := controlval.CorrelationKey{RunID: "r1", Target: "ws01", Action: tech.ID}
	provider := &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
		tech.ID: {Outcome: controlval.OutcomeBlocked, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}}
	o, err := provider.Observe(context.Background(), key)
	v := controlval.Evaluate(PreventionExpectationFor(tech), &o, err)
	result := PreventionFromValidation(tech, v)
	if result.Capability != CapabilityPrevention {
		t.Fatalf("capability = %q, want prevention", result.Capability)
	}
	if result.TechniqueID != "T1490" {
		t.Fatalf("techniqueID = %q, want T1490", result.TechniqueID)
	}
	if result.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (Defender blocked the attempt)", result.Verdict)
	}
	if result.Provenance != key {
		t.Fatalf("provenance = %+v, want %+v", result.Provenance, key)
	}
}

func TestPreventionFromValidation_NeverOverridesVerdict(t *testing.T) {
	// Adapter-only discipline: a FAIL stays FAIL, never recomputed.
	tech := VSSInhibition()
	allowed := &controlval.Observation{Outcome: controlval.OutcomeAllowed, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh}
	v := controlval.Evaluate(PreventionExpectationFor(tech), allowed, nil)
	result := PreventionFromValidation(tech, v)
	if result.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (control allowed a destructive attempt through)", result.Verdict)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run Prevention -v`
Expected: build failure — `undefined: PreventionExpectationFor`, `undefined: PreventionFromValidation`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/rwevidence/prevention.go`:

```go
package rwevidence

import "github.com/audspect/bas/internal/controlval"

// PreventionExpectationFor builds the controlval.Expectation for tech's
// Prevention capability: an authorized test identity's destructive attempt
// is expected to be Blocked by the deployed control.
func PreventionExpectationFor(tech Technique) controlval.Expectation {
	return controlval.Expectation{
		Expected:      controlval.OutcomeBlocked,
		MinConfidence: controlval.ConfidenceHigh,
	}
}

// PreventionFromValidation adapts an existing controlval.Validation
// (already produced by controlval.Evaluate against some Provider) into a
// Prevention CapabilityResult. It only translates -- it never recomputes or
// overrides what Evaluate already decided.
func PreventionFromValidation(tech Technique, v controlval.Validation) CapabilityResult {
	return CapabilityResult{
		Capability:  CapabilityPrevention,
		TechniqueID: tech.MitreID,
		Verdict:     v.Verdict,
		SkipReason:  v.SkipReason,
		Reason:      v.Reason,
		Provenance:  v.Key,
	}
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/rwevidence/prevention.go orchestrator/internal/rwevidence/prevention_test.go
git commit -m "feat(rwevidence): Prevention capability as an adapter to controlval

Goes through the existing controlval.Evaluate + FakeProvider -- no new
provider machinery. PreventionFromValidation only translates; it never
recomputes or overrides what Evaluate already decided."
git push
```

---

### Task 4: Recovery — its own verification contract

**Files:**
- Create: `orchestrator/internal/rwevidence/recovery.go`
- Test: `orchestrator/internal/rwevidence/recovery_test.go`

**Interfaces:**
- Consumes: `Technique`, `CapabilityResult`, `CapabilityRecovery`, `AttemptKey` (Task 2); `controlval.Verdict*`, `controlval.SkipReason*` (Task 1).
- Produces: `SurvivalResult` + 3 constants; `RecoveryObserver` interface; `FakeRecoveryObserver{Results, Err}`; `RecoveryFromSurvival(tech Technique, result SurvivalResult, corroboratingDetail string) CapabilityResult`; `RecoveryResultFor(tech Technique, result SurvivalResult, obsErr error, corroboratingDetail string) CapabilityResult`. Task 5's end-to-end test calls `FakeRecoveryObserver.ObserveSurvival` and `RecoveryFromSurvival` by these exact names.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwevidence/recovery_test.go`:

```go
package rwevidence

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestFakeRecoveryObserver_ReturnsCannedResult(t *testing.T) {
	key := AttemptKey{RunID: "r1", TechniqueID: "T1490"}
	f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{"r1/T1490": SurvivalConfirmed}}
	got, err := f.ObserveSurvival(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if got != SurvivalConfirmed {
		t.Fatalf("result = %q, want confirmed", got)
	}
}

func TestFakeRecoveryObserver_UncapturedKeyIsIndeterminate(t *testing.T) {
	f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{"other/x": SurvivalConfirmed}}
	got, err := f.ObserveSurvival(context.Background(), AttemptKey{RunID: "r2", TechniqueID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got != SurvivalIndeterminate {
		t.Fatalf("result = %q, want indeterminate (never guessed from another key's data)", got)
	}
}

func TestFakeRecoveryObserver_ConfiguredErrorPropagates(t *testing.T) {
	f := &FakeRecoveryObserver{Err: map[string]error{"boom/x": errors.New("wmi unreachable")}}
	if _, err := f.ObserveSurvival(context.Background(), AttemptKey{RunID: "boom", TechniqueID: "x"}); err == nil {
		t.Fatal("expected the configured error to propagate")
	}
}

func TestRecoveryFromSurvival_ConfirmedIsPass(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "")
	if cr.Capability != CapabilityRecovery {
		t.Fatalf("capability = %q, want recovery", cr.Capability)
	}
	if cr.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for PASS", cr.SkipReason)
	}
}

func TestRecoveryFromSurvival_LostIsFail(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalLost, "")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for FAIL", cr.SkipReason)
	}
}

func TestRecoveryFromSurvival_IndeterminateIsSkippedInsufficientEvidence(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalIndeterminate, "")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipInsufficientEvidence {
		t.Fatalf("skipReason = %q, want insufficient_evidence", cr.SkipReason)
	}
}

func TestRecoveryFromSurvival_CorroborationNeverChangesVerdict(t *testing.T) {
	withCorrob := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "vss-delete-edr fired")
	withoutCorrob := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "")
	if withCorrob.Verdict != withoutCorrob.Verdict {
		t.Fatalf("corroboration changed the verdict: %q vs %q", withCorrob.Verdict, withoutCorrob.Verdict)
	}
}

func TestRecoveryFromSurvival_ReasonNeverGeneralizesBeyondTargetedData(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "")
	if !strings.Contains(cr.Reason, "not a claim about overall backup recoverability") {
		t.Fatalf("reason = %q, must explicitly scope the claim", cr.Reason)
	}
}

func TestRecoveryResultFor_ObserverErrorTakesPrecedence(t *testing.T) {
	cr := RecoveryResultFor(VSSInhibition(), SurvivalConfirmed, errors.New("wmi unreachable"), "")
	if cr.Verdict != controlval.VerdictError {
		t.Fatalf("verdict = %q, want ERROR (operational failure takes precedence over any SurvivalResult)", cr.Verdict)
	}
}

func TestRecoveryResultFor_NoErrorDelegatesToSurvivalResult(t *testing.T) {
	cr := RecoveryResultFor(VSSInhibition(), SurvivalLost, nil, "")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run Recovery -v`
Expected: build failure — `undefined: SurvivalConfirmed`, `undefined: FakeRecoveryObserver`, `undefined: RecoveryFromSurvival`, `undefined: RecoveryResultFor`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/rwevidence/recovery.go`:

```go
package rwevidence

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
)

// SurvivalResult is whether the recovery mechanisms targeted by an
// authorized T1490 attempt (the specific shadow copies / backup catalog
// entries involved) survived.
type SurvivalResult string

const (
	SurvivalConfirmed     SurvivalResult = "confirmed"     // targeted copies/catalog entries still present
	SurvivalLost          SurvivalResult = "lost"          // confirmed destroyed
	SurvivalIndeterminate SurvivalResult = "indeterminate" // could not verify either way
)

// RecoveryObserver observes whether the targeted recovery mechanisms
// survived an authorized attempt. No real implementation ships in this
// slice -- enumerating real shadow copies/backup catalogs needs a live
// endpoint.
type RecoveryObserver interface {
	ObserveSurvival(ctx context.Context, key AttemptKey) (SurvivalResult, error)
}

// FakeRecoveryObserver is the only observer in this slice, keyed by
// RunID+"/"+TechniqueID. An uncaptured key returns SurvivalIndeterminate --
// never guessed Confirmed or Lost from another key's data.
type FakeRecoveryObserver struct {
	Results map[string]SurvivalResult
	Err     map[string]error
}

func recoveryKey(key AttemptKey) string {
	return key.RunID + "/" + key.TechniqueID
}

func (f *FakeRecoveryObserver) ObserveSurvival(_ context.Context, key AttemptKey) (SurvivalResult, error) {
	k := recoveryKey(key)
	if err, ok := f.Err[k]; ok {
		return "", err
	}
	if r, ok := f.Results[k]; ok {
		return r, nil
	}
	return SurvivalIndeterminate, nil
}

// recoveryScopeNote is appended to every Recovery Reason so no caller can
// read a Confirmed/Lost result as a claim about overall backup posture.
const recoveryScopeNote = "scoped to the specific shadow copies/backup catalog entries targeted by this authorized attempt -- not a claim about overall backup recoverability"

// RecoveryFromSurvival grades the Recovery capability for tech from a
// SurvivalResult. corroboratingDetail (e.g. the existing
// windows_vss_inhibition detection-profile alerts) rides along in Reason as
// supporting detail ONLY -- it never changes the Verdict by itself, same
// invariant as DCSync's 4662 corroboration and latmove's
// SecondaryLogObserved.
func RecoveryFromSurvival(tech Technique, result SurvivalResult, corroboratingDetail string) CapabilityResult {
	cr := CapabilityResult{Capability: CapabilityRecovery, TechniqueID: tech.MitreID}
	switch result {
	case SurvivalConfirmed:
		cr.Verdict = controlval.VerdictPass
		cr.Reason = "targeted recovery data survived the attempt (" + recoveryScopeNote + ")"
	case SurvivalLost:
		cr.Verdict = controlval.VerdictFail
		cr.Reason = "targeted recovery data was destroyed (" + recoveryScopeNote + ")"
	default:
		cr.Verdict = controlval.VerdictSkipped
		cr.SkipReason = controlval.SkipInsufficientEvidence
		cr.Reason = "could not verify survival either way (" + recoveryScopeNote + ")"
	}
	if corroboratingDetail != "" {
		cr.Reason += "; corroboration: " + corroboratingDetail
	}
	return cr
}

// RecoveryResultFor combines an observer's outcome and technical error into
// a Recovery CapabilityResult. An operational error takes precedence over
// any SurvivalResult, same error-precedence rule controlval.Evaluate
// enforces for opErr.
func RecoveryResultFor(tech Technique, result SurvivalResult, obsErr error, corroboratingDetail string) CapabilityResult {
	if obsErr != nil {
		return CapabilityResult{
			Capability:  CapabilityRecovery,
			TechniqueID: tech.MitreID,
			Verdict:     controlval.VerdictError,
			Reason:      "recovery observation failed: " + obsErr.Error(),
		}
	}
	return RecoveryFromSurvival(tech, result, corroboratingDetail)
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/rwevidence/recovery.go orchestrator/internal/rwevidence/recovery_test.go
git commit -m "feat(rwevidence): Recovery capability's own verification contract

Primary evidence is direct before/after survival of the TARGETED shadow
copies/backup catalog -- 'verify postconditions, not command-success,'
same discipline as DCSync's DRSUAPI-primary rule and latmove's
marker-readback. Detection-profile corroboration rides in Reason only,
never changes the Verdict. RecoveryResultFor enforces operational-error
precedence over any SurvivalResult, mirroring controlval.Evaluate's opErr
handling. Every Reason explicitly scopes the claim so it can never be
read as 'backup systems are recoverable.'"
git push
```

---

### Task 5: Detection (thin wrapper) + end-to-end + independence regression

**Files:**
- Create: `orchestrator/internal/rwevidence/detection.go`
- Test: `orchestrator/internal/rwevidence/detection_test.go`
- Test: `orchestrator/internal/rwevidence/vertical_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2-4 (`Technique`, `CapabilityResult`, `CapabilityDetection`, `PreventionExpectationFor`, `PreventionFromValidation`, `FakeRecoveryObserver`, `RecoveryFromSurvival`, `AttemptKey`) plus `controlval.FakeProvider`, `controlval.Evaluate`, `controlval.CorrelationKey`.
- Produces: `DetectionFromProfileResult(tech Technique, tested bool, profileVerified bool, reason string) CapabilityResult`. Nothing later in this plan consumes it further — this is the last production file in the slice.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwevidence/detection_test.go`:

```go
package rwevidence

import (
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestDetectionFromProfileResult_VerifiedIsPass(t *testing.T) {
	cr := DetectionFromProfileResult(VSSInhibition(), true, true, "Defender verified vss-delete-edr")
	if cr.Capability != CapabilityDetection {
		t.Fatalf("capability = %q, want detection", cr.Capability)
	}
	if cr.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for PASS", cr.SkipReason)
	}
}

func TestDetectionFromProfileResult_NotVerifiedIsFail(t *testing.T) {
	cr := DetectionFromProfileResult(VSSInhibition(), true, false, "Defender did not alert")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for FAIL", cr.SkipReason)
	}
}

func TestDetectionFromProfileResult_NotTestedIsSkippedNotTested(t *testing.T) {
	cr := DetectionFromProfileResult(VSSInhibition(), false, false, "")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipNotTested {
		t.Fatalf("skipReason = %q, want not_tested", cr.SkipReason)
	}
}
```

Create `orchestrator/internal/rwevidence/vertical_test.go`:

```go
package rwevidence

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestEndToEnd_VSSInhibition_ThreeCapabilitiesIndependentlyVerified(t *testing.T) {
	tech := VSSInhibition()
	key := controlval.CorrelationKey{RunID: "r-vss", Target: "ws01", Action: tech.ID}

	// Prevention: Defender blocked the vssadmin delete attempt.
	provider := &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
		tech.ID: {Outcome: controlval.OutcomeBlocked, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}}
	o, err := provider.Observe(context.Background(), key)
	prevention := PreventionFromValidation(tech, controlval.Evaluate(PreventionExpectationFor(tech), &o, err))
	prevention.Provenance = key

	// Recovery: the targeted shadow copies survived.
	recoveryObs := &FakeRecoveryObserver{Results: map[string]SurvivalResult{"r-vss/" + tech.MitreID: SurvivalConfirmed}}
	survival, rerr := recoveryObs.ObserveSurvival(context.Background(), AttemptKey{RunID: "r-vss", TechniqueID: tech.MitreID})
	if rerr != nil {
		t.Fatal(rerr)
	}
	recovery := RecoveryFromSurvival(tech, survival, "")
	recovery.Provenance = key

	// Detection: the windows_vss_inhibition profile verified.
	detection := DetectionFromProfileResult(tech, true, true, "vss-delete-edr fired")
	detection.Provenance = key

	for _, cr := range []CapabilityResult{prevention, recovery, detection} {
		if cr.TechniqueID != "T1490" {
			t.Fatalf("%s: techniqueID = %q, want T1490", cr.Capability, cr.TechniqueID)
		}
		if cr.Provenance != key {
			t.Fatalf("%s: provenance = %+v, want %+v", cr.Capability, cr.Provenance, key)
		}
	}
	if prevention.Verdict != controlval.VerdictPass || recovery.Verdict != controlval.VerdictPass || detection.Verdict != controlval.VerdictPass {
		t.Fatalf("expected all PASS: prevention=%q recovery=%q detection=%q", prevention.Verdict, recovery.Verdict, detection.Verdict)
	}
}

func TestIndependence_PreventionAndRecoveryNeverCrossContaminate(t *testing.T) {
	tech := VSSInhibition()
	key := controlval.CorrelationKey{RunID: "r-mixed", Target: "ws01", Action: tech.ID}

	// Prevention FAILS: Defender allowed the destructive attempt through.
	provider := &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
		tech.ID: {Outcome: controlval.OutcomeAllowed, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}}
	o, err := provider.Observe(context.Background(), key)
	prevention := PreventionFromValidation(tech, controlval.Evaluate(PreventionExpectationFor(tech), &o, err))

	// Recovery PASSES independently: despite the attempt getting through,
	// the targeted shadow copies still survived (e.g. a backup-side
	// protection caught what the endpoint control missed).
	recovery := RecoveryFromSurvival(tech, SurvivalConfirmed, "")

	if prevention.Verdict != controlval.VerdictFail {
		t.Fatalf("prevention verdict = %q, want FAIL", prevention.Verdict)
	}
	if recovery.Verdict != controlval.VerdictPass {
		t.Fatalf("recovery verdict = %q, want PASS -- a Prevention FAIL must never be allowed to drag Recovery down", recovery.Verdict)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: build failure — `undefined: DetectionFromProfileResult` (the `vertical_test.go` cases fail to compile for the same reason, since the package fails to build as a whole).

- [ ] **Step 3: Implement**

Create `orchestrator/internal/rwevidence/detection.go`:

```go
package rwevidence

import "github.com/audspect/bas/internal/controlval"

// DetectionFromProfileResult wraps the existing windows_vss_inhibition
// detection-profile verification result (already live, Microsoft-Defender
// auto-verified, wired across all 7 ransomware scenarios) into a Detection
// CapabilityResult. No new detection plumbing in this slice -- a
// detectverify-based rwdetect bridge (mirroring latdetect/addetect) for
// real alert-latency measurement is a separable later phase.
//
// tested distinguishes "the profile ran and gave a definitive result" from
// "nothing has evaluated this yet": when tested is false, profileVerified
// is ignored and the result is Skipped/SkipNotTested.
func DetectionFromProfileResult(tech Technique, tested bool, profileVerified bool, reason string) CapabilityResult {
	cr := CapabilityResult{Capability: CapabilityDetection, TechniqueID: tech.MitreID, Reason: reason}
	switch {
	case !tested:
		cr.Verdict = controlval.VerdictSkipped
		cr.SkipReason = controlval.SkipNotTested
	case profileVerified:
		cr.Verdict = controlval.VerdictPass
	default:
		cr.Verdict = controlval.VerdictFail
	}
	return cr
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS, all tests across the package including the end-to-end and independence tests.

- [ ] **Step 5: Full-suite verification and commit**

Run: `cd orchestrator && go vet ./internal/rwevidence/ ./internal/controlval/ && gofmt -l ./internal/rwevidence/ ./internal/controlval/ && go build ./...`
Expected: `go vet` silent, `gofmt -l` prints nothing (clean), `go build ./...` exits 0.

Run: `cd orchestrator && go test ./internal/rwevidence/ ./internal/controlval/ ./internal/adcontrolval/ ./internal/latmove/ ./internal/adefficacy/ ./internal/adprimitive/`
Expected: `ok` for all 6 packages.

```bash
git add orchestrator/internal/rwevidence/detection.go orchestrator/internal/rwevidence/detection_test.go orchestrator/internal/rwevidence/vertical_test.go
git commit -m "feat(rwevidence): Detection capability + T1490 end-to-end vertical proof

DetectionFromProfileResult thinly wraps the existing windows_vss_inhibition
profile result -- no new detection plumbing. End-to-end test proves all
three capabilities (Prevention/Recovery/Detection) are independently
derived for one T1490 attempt, sharing one CorrelationKey. Independence
regression test locks the core invariant: a Prevention FAIL must never
drag down an independently-PASSing Recovery for the same attempt, and
vice versa."
git push
```

---

## Completion

After Task 5, the T1490 vertical slice is complete: `controlval` has a canonical `SkipReason` with zero breakage to existing consumers, and `rwevidence` proves Prevention/Recovery/Detection as three independently-verified capability dimensions for one technique, fake-backed throughout. Nothing in this plan executes anything, changes scenario content, or touches `admatrix`/`adcontrolval`/scoring. Containment, DataProtection, real observers, and any UI work remain explicitly deferred to later phases per the spec.
