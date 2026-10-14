# rwevidence Scenario-Dispatch Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Execution method already decided: native/inline (standing session preference) — do not ask the human partner to choose.

**Goal:** Wire `rwevidence`'s existing fake-backed evaluators into real scenario dispatch for the first time (true of every mastery evidence engine in this codebase, not just rwevidence), so the 8 existing ransomware scenarios produce persisted `rw_capability_results` rows alongside — never replacing — their existing `models.SimulationResult`/`CheckResult` outcome.

**Architecture:** A new `rwevidence.EvaluateStep` function classifies each technique-tagged step (modeled vs. unmapped, attempt vs. recon, which safety-gate/precondition pattern matched) and, for a genuine T1490/T1486/T1567.002 attempt, calls the existing capability evaluators with fake-backed observer dependencies injected by the caller. Results persist to a new `rw_capability_results` table via a plain upsert function in `internal/db`, called from the one real call site where `scenario.Interpret` already runs inside `internal/api/handlers.go`.

**Tech Stack:** Go, PostgreSQL (`pgxpool.Pool`), existing `rwevidence`/`controlval`/`scenario`/`models` packages.

**Spec:** `docs/superpowers/specs/2026-10-11-rwevidence-scenario-dispatch-integration-design.md`

## Global Constraints

- Modeled techniques are exactly T1490, T1486, T1567.002 (`rwevidence.VSSInhibition()`/`DataEncryptedForImpact()`/`DataExfiltrationToCloud()`) — no new techniques, no new real observers, no scoring/UI work.
- `models.SimulationResult`/`CheckResult` (the existing dispatch outcome, produced by `scenario.Interpret`) is read-only to this work — never modified, never derived from `rw_capability_results`.
- Every `rw_capability_results` row this plan ever writes has `simulated = true`. No task flips it to `false`.
- The canonical 4-verdict taxonomy (`controlval.Verdict` PASS/FAIL/ERROR/SKIPPED) plus `controlval.SkipReason` (insufficient_evidence/not_applicable/not_tested) is the only typed state — no competing `result_state` column. The 7 situations in the spec's table (section B) are distinguished by a `specific_reason` short code column, separate from the existing free-text `Reason`.
- `rwevidence` package stays pure Go, stdlib + existing internal deps only (`adprimitive`, `controlval`) — no `pgx`/`db` import. Persistence lives in `internal/db`, which imports `rwevidence` for the type, never the reverse.
- `AttemptKey`'s `Action` field is `scenario.TaskID(step.TechniqueID, step.Name)` (existing function, `internal/scenario/builder.go:23`, `sha256(techniqueID|name)[:8]`) — reused, never reimplemented.

## Review Focus

- A technique-tagged step this plan has never seen before (any technique_id outside the 3 modeled ones, across any of the 8 scenario files) must still produce a complete, correctly-shaped row set — Task 7's full-corpus enumeration test is the only thing that actually proves this, not spot-checking a few files by hand.
- A step whose `models.SimulationResult.Details`/`RawOutput` text doesn't match ANY known skip pattern (not the VSS gate, not the "no shadow copies" precondition) must fall back to `skip_unclassified`, never silently default to `gate_not_confirmed` just because the step happened to skip — Task 2's classifier is the one place this can go wrong.
- Two steps in the same scenario run sharing a technique_id but doing genuinely different things (em-07's three T1490 actions) must never collapse into one row per capability — Task 1's Action field only fixes this if Task 3's evaluation calls actually thread it through; Task 7 pins this against the real file, not a synthetic fixture.
- A DB write failure partway through a step's capability set must not look like partial success to anything reading `rw_capability_results` afterward — Task 5's error-surfacing and Task 7's simulated-failure test are the only things that catch a "some rows silently missing" regression.
- `T1486`×DataProtection and `T1567.002`×{Prevention, Recovery, Detection} (the 4 genuinely undecided applicability pairs found during spec self-review) must come out as `applicability_undecided`, not get silently merged into `technique_not_mapped` (wrong — the technique IS modeled) or `not_applicable` (wrong — that asserts a decided "no" that was never made). Task 3 is where this is easiest to get wrong by reusing the wrong helper.

---

### Task 1: `AttemptKey` gains `Action`

**Files:**
- Modify: `orchestrator/internal/rwevidence/types.go` (`AttemptKey` struct)
- Modify: `orchestrator/internal/rwevidence/recovery.go` (`recoveryKey`)
- Modify: `orchestrator/internal/rwevidence/containment.go` (`containmentKey`)
- Modify: `orchestrator/internal/rwevidence/recovery_test.go` (key literals → built via `recoveryKey`)
- Modify: `orchestrator/internal/rwevidence/containment_test.go` (key literals → built via `containmentKey`)
- Test: `orchestrator/internal/rwevidence/types_test.go` (new)

**Interfaces:**
- Consumes: nothing new.
- Produces: `AttemptKey{RunID, TechniqueID, Action string}` — Task 3 and Task 7 construct this with `Action: scenario.TaskID(step.TechniqueID, step.Name)`.

- [ ] **Step 1: Write the failing test proving two actions under one technique stay independent**

Create `orchestrator/internal/rwevidence/types_test.go`:

```go
package rwevidence

import "testing"

func TestFakeRecoveryObserver_DifferentActionsSameTechniqueStayIndependent(t *testing.T) {
	f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{
		recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "aaa11111"}): SurvivalConfirmed,
		recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "bbb22222"}): SurvivalLost,
	}}
	got1, err1 := f.ObserveSurvival(nil, AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "aaa11111"})
	if err1 != nil || got1 != SurvivalConfirmed {
		t.Fatalf("action aaa11111: got %q, err %v, want confirmed", got1, err1)
	}
	got2, err2 := f.ObserveSurvival(nil, AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "bbb22222"})
	if err2 != nil || got2 != SurvivalLost {
		t.Fatalf("action bbb22222: got %q, err %v, want lost -- two actions sharing a technique must never collapse into one result", got2, err2)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestFakeRecoveryObserver_DifferentActionsSameTechniqueStayIndependent -v`
Expected: FAIL — `unknown field Action in struct literal` (compile error; `AttemptKey` has no `Action` field yet)

- [ ] **Step 3: Add `Action` to `AttemptKey` and thread it through both key builders**

In `orchestrator/internal/rwevidence/types.go`, change:

```go
// AttemptKey identifies one technique attempt, for correlating independent
// observers (Recovery, ...) against the same event.
type AttemptKey struct {
	RunID       string
	TechniqueID string
}
```

to:

```go
// AttemptKey identifies one technique attempt, for correlating independent
// observers (Recovery, Containment, ...) against the same event. Action
// distinguishes multiple distinct attempts sharing one technique within the
// same run (e.g. em-07's three independent T1490 steps: shadow-copy
// deletion, wbadmin catalog deletion, bcdedit disable) -- without it they
// collapse onto one result. Action is scenario.TaskID(step.TechniqueID,
// step.Name), reused from the existing step-identity mechanism, never
// reimplemented here.
type AttemptKey struct {
	RunID       string
	TechniqueID string
	Action      string
}
```

In `orchestrator/internal/rwevidence/recovery.go`, change:

```go
func recoveryKey(key AttemptKey) string {
	return key.RunID + "/" + key.TechniqueID
}
```

to:

```go
func recoveryKey(key AttemptKey) string {
	return key.RunID + "/" + key.TechniqueID + "/" + key.Action
}
```

In `orchestrator/internal/rwevidence/containment.go`, make the identical change to `containmentKey`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestFakeRecoveryObserver_DifferentActionsSameTechniqueStayIndependent -v`
Expected: PASS

- [ ] **Step 5: Fix the existing tests broken by the key-format change**

`recovery_test.go` and `containment_test.go` build their observers' `Results`/`Err` maps with hand-written string literals (e.g. `"r1/T1490"`, `"other/x"`, `"boom/x"`) that assumed the old two-segment format. These must change to build keys through the helper instead of hardcoding the format a second time.

In `orchestrator/internal/rwevidence/recovery_test.go`, change every occurrence of a hand-written key string to call `recoveryKey(...)`. For example:

```go
f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{"r1/T1490": SurvivalConfirmed}}
got, err := f.ObserveSurvival(context.Background(), AttemptKey{RunID: "r1", TechniqueID: "T1490"})
```

becomes:

```go
key := AttemptKey{RunID: "r1", TechniqueID: "T1490"}
f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{recoveryKey(key): SurvivalConfirmed}}
got, err := f.ObserveSurvival(context.Background(), key)
```

Apply the same change to `TestFakeRecoveryObserver_UncapturedKeyIsIndeterminate` and `TestFakeRecoveryObserver_ConfiguredErrorPropagates`, and to the equivalent three tests in `containment_test.go` (`TestFakeContainmentObserver_ReturnsCannedResult`, `_UncapturedKeyIsIndeterminate`, `_ConfiguredErrorPropagates`). None of these tests need `Action` set to a non-empty value — they're testing the uncaptured/error-propagation paths, not multi-action disambiguation — so leaving `Action` as its zero value `""` in their `AttemptKey` literals is correct and matches the Review Focus item about not inventing scope beyond what each test actually needs.

- [ ] **Step 6: Run the full package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS, all tests (including `TestEndToEnd_VSSInhibition_ThreeCapabilitiesIndependentlyVerified`, `TestEndToEnd_GeneralizesToASecondTechnique`, `TestIndependence_PreventionAndRecoveryNeverCrossContaminate`, which construct `AttemptKey` inline and are unaffected since they don't hand-write key strings)

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/rwevidence/types.go internal/rwevidence/recovery.go internal/rwevidence/containment.go internal/rwevidence/recovery_test.go internal/rwevidence/containment_test.go internal/rwevidence/types_test.go
git commit -m "feat(rwevidence): AttemptKey gains Action, distinguishing multiple attempts under one technique

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: `EvaluateStep` — classification skeleton (modeled / attempt-vs-recon / skip-pattern)

**Files:**
- Create: `orchestrator/internal/rwevidence/dispatch.go`
- Create: `orchestrator/internal/rwevidence/dispatch_test.go`

**Interfaces:**
- Consumes: `Technique`, `CapabilityResult`, `NotApplicable`, `NotTested` (existing, `types.go`/`technique.go`).
- Produces: `StepInput{TechniqueID, StepName, Action, RunID, CheckResult, Details string}` (the minimal fields `EvaluateStep` needs — deliberately NOT `scenario.Step`/`models.SimulationResult` directly, so `rwevidence` never imports `scenario` or `models`; the caller in Task 5 maps those real types onto `StepInput`). `classifyRansomwareStep(in StepInput) (modeled bool, isAttempt bool, skipReason string, specificReason string)` — Task 3 calls this first, before doing any real evaluation.

This task builds the branching logic in isolation, returning only `NotTested`/`NotApplicable`-shaped results — no real evaluator calls yet (that's Task 3). It is the one task Review Focus's second and third bullets are about, so get it right here before Task 3 adds more surface on top.

- [ ] **Step 1: Write the failing tests for each classification branch**

Create `orchestrator/internal/rwevidence/dispatch_test.go`:

```go
package rwevidence

import "testing"

func TestClassify_UnmodeledTechnique(t *testing.T) {
	in := StepInput{TechniqueID: "T1059", StepName: "PowerShell Execution", RunID: "r1", Action: "x", CheckResult: "fail"}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if modeled {
		t.Fatal("T1059 is not one of the 3 modeled techniques")
	}
	if isAttempt {
		t.Fatal("an unmodeled technique is never classified as an attempt")
	}
	if specificReason != "technique_not_mapped" {
		t.Fatalf("specificReason = %q, want technique_not_mapped", specificReason)
	}
}

func TestClassify_ReconnaissanceStep(t *testing.T) {
	in := StepInput{TechniqueID: "T1490", StepName: "VSS Snapshot Enumeration", RunID: "r1", Action: "x", CheckResult: "pass"}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled {
		t.Fatal("T1490 is modeled")
	}
	if isAttempt {
		t.Fatal("an enumeration step is not an attempt")
	}
	if specificReason != "not_an_attempt" {
		t.Fatalf("specificReason = %q, want not_an_attempt", specificReason)
	}
}

func TestClassify_GateNotConfirmed(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true' - WMI-based VSS deletion skipped (default-disabled per ransomware safety policy).",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true (this IS the destructive attempt step, it just didn't run)", modeled, isAttempt)
	}
	if specificReason != "gate_not_confirmed" {
		t.Fatalf("specificReason = %q, want gate_not_confirmed", specificReason)
	}
}

func TestClassify_NoTargetPrecondition(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: no C: VSS shadow copies exist - nothing to delete. Create a snapshot first with: vssadmin create shadow /for=C:",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true", modeled, isAttempt)
	}
	if specificReason != "no_target_precondition" {
		t.Fatalf("specificReason = %q, want no_target_precondition", specificReason)
	}
}

func TestClassify_UnrecognizedSkipFallsBackConservatively(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: some future condition this classifier has never seen before",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true", modeled, isAttempt)
	}
	if specificReason != "skip_unclassified" {
		t.Fatalf("specificReason = %q, want skip_unclassified -- an unrecognized skip must never be guessed into gate_not_confirmed", specificReason)
	}
}

func TestClassify_AttemptThatRan(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "fail",
		Details:     "FAIL: deleted 1 shadow copy, control did not intervene",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true", modeled, isAttempt)
	}
	if specificReason != "" {
		t.Fatalf("specificReason = %q, want empty -- this attempt ran, there's no coverage-gap reason to record", specificReason)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestClassify -v`
Expected: FAIL — `undefined: StepInput`, `undefined: classifyRansomwareStep` (compile error)

- [ ] **Step 3: Implement `StepInput` and `classifyRansomwareStep`**

Create `orchestrator/internal/rwevidence/dispatch.go`:

```go
package rwevidence

import "strings"

// StepInput is the minimal shape EvaluateStep needs from one dispatched
// scenario step's outcome. The caller (internal/api) maps its own
// scenario.Step/models.SimulationResult onto this -- rwevidence never
// imports scenario or models, keeping it a pure evidence/logic package.
type StepInput struct {
	RunID       string
	Action      string // scenario.TaskID(step.TechniqueID, step.Name), built by the caller
	TechniqueID string
	StepName    string
	CheckResult string // "pass"/"fail"/"skipped"/"error"/"vetoed", mirrors models.CheckResult's string values
	Details     string // the step's raw output/detail text, for skip-pattern matching
}

// reconnaissanceStepNames are the modeled-technique steps that only
// enumerate/observe and never attempt the destructive behavior. Matched
// against StepInput.StepName.
var reconnaissanceStepNames = map[string]bool{
	"VSS Snapshot Enumeration":        true,
	"VSS + Backup Catalog Enumeration": true,
}

// classifyRansomwareStep is the first stage of EvaluateStep's decision tree
// (spec section B, rules 1-3). modeled reports whether TechniqueID is one of
// the 3 this package supports. isAttempt reports whether this step tried
// the destructive/attempted behavior (false for recon and for unmodeled
// techniques). specificReason is set whenever this function alone can
// already determine the row's fate without calling any evaluator --
// "technique_not_mapped", "not_an_attempt", "gate_not_confirmed",
// "no_target_precondition", or "skip_unclassified". It is empty when the
// attempt genuinely ran and needs real evaluation (Task 3).
func classifyRansomwareStep(in StepInput) (modeled bool, isAttempt bool, specificReason string) {
	switch in.TechniqueID {
	case "T1490", "T1486", "T1567.002":
		modeled = true
	default:
		return false, false, "technique_not_mapped"
	}

	if reconnaissanceStepNames[in.StepName] {
		return true, false, "not_an_attempt"
	}

	if in.CheckResult != "skipped" {
		return true, true, ""
	}

	lower := strings.ToLower(in.Details)
	switch {
	case strings.Contains(lower, "bas_confirm_vss_delete not set"):
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "no c: vss shadow copies exist"):
		return true, true, "no_target_precondition"
	default:
		return true, true, "skip_unclassified"
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestClassify -v`
Expected: PASS (6/6)

- [ ] **Step 5: Run the full package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/rwevidence/dispatch.go internal/rwevidence/dispatch_test.go
git commit -m "feat(rwevidence): classifyRansomwareStep -- modeled/attempt/skip-pattern classification

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: `EvaluateStep` — complete capability-set evaluation for genuine attempts

**Files:**
- Modify: `orchestrator/internal/rwevidence/dispatch.go`
- Modify: `orchestrator/internal/rwevidence/dispatch_test.go`

**Interfaces:**
- Consumes: `classifyRansomwareStep`, `StepInput` (Task 2); `PreventionExpectationFor`/`PreventionFromValidation` (`prevention.go`); `RecoveryResultFor` (`recovery.go`); `ContainmentResultFor` (`containment.go`); `DetectionFromProfileResult` (`detection.go`); `DataProtectionFromDLPResult` (`dataprotection.go`); `controlval.Provider`, `controlval.Evaluate`, `controlval.CorrelationKey` (existing, `controlval` package); `AttemptKey` (Task 1).
- Produces: `DetectionLookup`/`FakeDetectionLookup`, `DataProtectionLookup`/`FakeDataProtectionLookup` (new, this task); `StepDependencies{Prevention controlval.Provider; Recovery RecoveryObserver; Containment ContainmentObserver; Detection DetectionLookup; DataProtection DataProtectionLookup}`; `EvaluateStep(in StepInput, deps StepDependencies) []CapabilityResult` — Task 5's dispatch call site and Task 7's acceptance tests both call this directly.

Detection and DataProtection have no existing observer-style interface (their current functions take already-known bool/string values) -- this task adds the minimal fake-backed lookup interfaces needed to drive them from dispatch, matching `RecoveryObserver`'s existing shape exactly.

- [ ] **Step 1: Write the failing test for a full T1490 attempt producing the complete capability set**

Add to `orchestrator/internal/rwevidence/dispatch_test.go`, and add `"errors"` and `"github.com/audspect/bas/internal/controlval"` to this file's existing `import` block (it only has `"testing"` after Task 2):

```go
func TestEvaluateStep_T1490Attempt_ProducesCompleteCapabilitySet(t *testing.T) {
	in := StepInput{
		RunID: "r1", Action: "aaa11111", TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI",
		CheckResult: "fail", Details: "FAIL: deleted 1 shadow copy, control did not intervene",
	}
	deps := StepDependencies{
		Prevention: &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
			"aaa11111": {Outcome: controlval.OutcomeAllowed, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
		}},
		Recovery:   &FakeRecoveryObserver{Results: map[string]SurvivalResult{recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "aaa11111"}): SurvivalLost}},
		Containment: &FakeContainmentObserver{},
		Detection:   &FakeDetectionLookup{},
		DataProtection: &FakeDataProtectionLookup{},
	}
	results := EvaluateStep(in, deps)

	byCapability := map[Capability]CapabilityResult{}
	for _, r := range results {
		byCapability[r.Capability] = r
	}
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5 (one per capability, not_applicable/undecided included)", len(results))
	}
	if byCapability[CapabilityPrevention].Verdict != controlval.VerdictFail {
		t.Errorf("prevention = %+v, want FAIL (Defender allowed the attempt)", byCapability[CapabilityPrevention])
	}
	if byCapability[CapabilityRecovery].Verdict != controlval.VerdictFail {
		t.Errorf("recovery = %+v, want FAIL (SurvivalLost)", byCapability[CapabilityRecovery])
	}
	if byCapability[CapabilityContainment].SkipReason != controlval.SkipNotApplicable {
		t.Errorf("containment = %+v, want SKIPPED/not_applicable (T1490 has no Containment dimension)", byCapability[CapabilityContainment])
	}
	if byCapability[CapabilityDataProtection].SkipReason != controlval.SkipNotApplicable {
		t.Errorf("data_protection = %+v, want SKIPPED/not_applicable", byCapability[CapabilityDataProtection])
	}
	for _, r := range results {
		if r.TechniqueID != "T1490" {
			t.Errorf("%s: techniqueID = %q, want T1490", r.Capability, r.TechniqueID)
		}
	}
}

func TestEvaluateStep_T1567002Attempt_UndecidedCapabilitiesAreApplicabilityUndecided(t *testing.T) {
	in := StepInput{
		RunID: "r1", Action: "ccc33333", TechniqueID: "T1567.002", StepName: "Cloud Storage Egress Reachability",
		CheckResult: "fail", Details: "FAIL: reachable",
	}
	deps := StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &FakeRecoveryObserver{},
		Containment:    &FakeContainmentObserver{},
		Detection:      &FakeDetectionLookup{},
		DataProtection: &FakeDataProtectionLookup{Status: map[string]string{"r1/T1567.002/ccc33333": "NotDetected"}},
	}
	results := EvaluateStep(in, deps)
	byCapability := map[Capability]CapabilityResult{}
	for _, r := range results {
		byCapability[r.Capability] = r
	}
	for _, cap := range []Capability{CapabilityPrevention, CapabilityRecovery, CapabilityDetection} {
		r := byCapability[cap]
		if r.Verdict != controlval.VerdictSkipped || r.SkipReason != controlval.SkipNotTested {
			t.Errorf("%s = %+v, want SKIPPED/not_tested (applicability_undecided)", cap, r)
		}
	}
	if byCapability[CapabilityDataProtection].Verdict != controlval.VerdictFail {
		t.Errorf("data_protection = %+v, want FAIL (NotDetected)", byCapability[CapabilityDataProtection])
	}
}

func TestEvaluateStep_T1486Attempt_DataProtectionIsApplicabilityUndecided(t *testing.T) {
	// The other half of acceptance criterion 11 -- T1567.002's test above
	// covers its 3 undecided capabilities, this covers T1486's 1 (Recovery
	// is a DECIDED not_applicable for T1486, tested separately; DataProtection
	// was never decided either way).
	in := StepInput{
		RunID: "r1", Action: "eee55555", TechniqueID: "T1486", StepName: "Ransomware Payload Simulation",
		CheckResult: "fail", Details: "FAIL: files encrypted",
	}
	deps := StepDependencies{
		Prevention: &controlval.FakeProvider{}, Recovery: &FakeRecoveryObserver{},
		Containment: &FakeContainmentObserver{}, Detection: &FakeDetectionLookup{}, DataProtection: &FakeDataProtectionLookup{},
	}
	results := EvaluateStep(in, deps)
	var dataProtection, recovery CapabilityResult
	for _, r := range results {
		if r.Capability == CapabilityDataProtection {
			dataProtection = r
		}
		if r.Capability == CapabilityRecovery {
			recovery = r
		}
	}
	if dataProtection.Verdict != controlval.VerdictSkipped || dataProtection.SkipReason != controlval.SkipNotTested || dataProtection.SpecificReason != "applicability_undecided" {
		t.Fatalf("data_protection = %+v, want SKIPPED/not_tested/applicability_undecided", dataProtection)
	}
	if recovery.SpecificReason == "applicability_undecided" {
		t.Fatal("recovery is a DECIDED not_applicable for T1486, not an undecided case -- must not share recovery's specificReason with dataProtection's")
	}
}

func TestEvaluateStep_NotAnAttempt_ReturnsNotTestedForAllFiveCapabilities(t *testing.T) {
	in := StepInput{RunID: "r1", Action: "bbb22222", TechniqueID: "T1490", StepName: "VSS Snapshot Enumeration", CheckResult: "pass"}
	results := EvaluateStep(in, StepDependencies{})
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5", len(results))
	}
	for _, r := range results {
		if r.Verdict != controlval.VerdictSkipped || r.SkipReason != controlval.SkipNotTested {
			t.Errorf("%s = %+v, want SKIPPED/not_tested", r.Capability, r)
		}
	}
}

func TestEvaluateStep_EvaluatorErrorIsDistinctFromNotInvoked(t *testing.T) {
	// Acceptance criterion 7: an evaluator that ran and failed operationally
	// (ERROR) must be provably distinct from a capability that was never
	// invoked at all (SKIPPED/not_tested), even within the same result set.
	in := StepInput{
		RunID: "r1", Action: "ddd44444", TechniqueID: "T1486", StepName: "Ransomware Payload Simulation",
		CheckResult: "fail", Details: "FAIL: files encrypted",
	}
	key := recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1486", Action: "ddd44444"})
	deps := StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &FakeRecoveryObserver{}, // T1486: not_applicable, never invoked
		Containment:    &FakeContainmentObserver{},
		Detection:      &FakeDetectionLookup{Err: map[string]error{key: errors.New("detection profile service unreachable")}},
		DataProtection: &FakeDataProtectionLookup{}, // T1486: applicability_undecided, never invoked
	}
	results := EvaluateStep(in, deps)
	byCapability := map[Capability]CapabilityResult{}
	for _, r := range results {
		byCapability[r.Capability] = r
	}

	detection := byCapability[CapabilityDetection]
	if detection.Verdict != controlval.VerdictError {
		t.Fatalf("detection = %+v, want ERROR (the lookup was invoked and failed operationally)", detection)
	}
	recovery := byCapability[CapabilityRecovery]
	if recovery.Verdict != controlval.VerdictSkipped || recovery.SkipReason != controlval.SkipNotApplicable {
		t.Fatalf("recovery = %+v, want SKIPPED/not_applicable (never invoked at all, not an evaluation failure)", recovery)
	}
	if detection.Verdict == recovery.Verdict {
		t.Fatal("an evaluator that ran and errored must not be indistinguishable from one that was never invoked")
	}
}

func TestEvaluateStep_UnmodeledTechnique_ReturnsNotTestedForAllFiveCapabilities(t *testing.T) {
	in := StepInput{RunID: "r1", Action: "zzz99999", TechniqueID: "T1059", StepName: "PowerShell Execution", CheckResult: "fail"}
	results := EvaluateStep(in, StepDependencies{})
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5")
	}
	for _, r := range results {
		if r.SkipReason != controlval.SkipNotTested {
			t.Errorf("%s = %+v, want not_tested/technique_not_mapped", r.Capability, r)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestEvaluateStep -v`
Expected: FAIL — `undefined: StepDependencies`, `undefined: EvaluateStep`, `undefined: FakeDetectionLookup`, `undefined: FakeDataProtectionLookup` (compile error)

- [ ] **Step 3: Implement the lookups, dependencies struct, and `EvaluateStep`**

Append to `orchestrator/internal/rwevidence/dispatch.go`:

```go
import (
	"context"
	"strings"

	"github.com/audspect/bas/internal/controlval"
)

// DetectionLookup stands in for a real detection-profile query (the
// existing windows_vss_inhibition-style verification) until a real
// rwdetect bridge lands -- fake-backed only in this slice, same discipline
// as RecoveryObserver.
type DetectionLookup interface {
	LookupDetection(ctx context.Context, key AttemptKey) (tested bool, verified bool, reason string, err error)
}

// FakeDetectionLookup is keyed exactly like FakeRecoveryObserver: an
// uncaptured key means "never evaluated", not a guessed verdict.
type FakeDetectionLookup struct {
	Tested   map[string]bool
	Verified map[string]bool
	Reason   map[string]string
	Err      map[string]error
}

func (f *FakeDetectionLookup) LookupDetection(_ context.Context, key AttemptKey) (bool, bool, string, error) {
	k := recoveryKey(key) // same RunID/TechniqueID/Action identity, reused rather than reinvented
	if err, ok := f.Err[k]; ok {
		return false, false, "", err
	}
	return f.Tested[k], f.Verified[k], f.Reason[k], nil
}

// DataProtectionLookup stands in for a real DLP Validation Suite query
// until this is wired to reporting's actual VerificationResult -- fake-
// backed only in this slice.
type DataProtectionLookup interface {
	LookupDataProtection(ctx context.Context, key AttemptKey) (status string, reason string, err error)
}

// FakeDataProtectionLookup: an uncaptured key returns "" (which
// DataProtectionFromDLPResult already treats as unrecognized -> fail-closed
// SkipInsufficientEvidence), never a guessed status.
type FakeDataProtectionLookup struct {
	Status map[string]string
	Reason map[string]string
	Err    map[string]error
}

func (f *FakeDataProtectionLookup) LookupDataProtection(_ context.Context, key AttemptKey) (string, string, error) {
	k := recoveryKey(key)
	if err, ok := f.Err[k]; ok {
		return "", "", err
	}
	return f.Status[k], f.Reason[k], nil
}

// StepDependencies bundles the fake-backed observers/lookups EvaluateStep
// needs for a genuine attempt. All 5 are nil-safe: a zero-value
// StepDependencies is fine for a step that classifyRansomwareStep already
// resolved without needing any of them (recon, unmodeled, gated, etc).
type StepDependencies struct {
	Prevention     controlval.Provider
	Recovery       RecoveryObserver
	Containment    ContainmentObserver
	Detection      DetectionLookup
	DataProtection DataProtectionLookup
}

var allCapabilities = []Capability{
	CapabilityPrevention, CapabilityDetection, CapabilityContainment,
	CapabilityRecovery, CapabilityDataProtection,
}

// undecidedApplicability names the (technique, capability) pairs with no
// decided applicability rule in the existing code -- found during this
// sub-project's spec self-review. Never invented here; each pair is
// recorded as SKIPPED/not_tested/applicability_undecided, distinct from
// both not_applicable (a decided no) and technique_not_mapped (the
// technique itself isn't modeled).
var undecidedApplicability = map[string]map[Capability]bool{
	"T1486":     {CapabilityDataProtection: true},
	"T1567.002": {CapabilityPrevention: true, CapabilityRecovery: true, CapabilityDetection: true},
}

// notApplicable names the (technique, capability) pairs with a DECIDED "no"
// in existing code (T1490's Containment/DataProtection, T1486's Recovery,
// T1567.002's Containment).
var notApplicable = map[string]map[Capability]string{
	"T1490":     {CapabilityContainment: "T1490 is a single-host VSS/backup-catalog deletion -- it has no lateral-reachability dimension to contain", CapabilityDataProtection: "T1490 destroys recovery mechanisms; it does not access, stage, or exfiltrate data"},
	"T1486":     {CapabilityRecovery: "T1486 is about whether files get encrypted, not whether recovery mechanisms survive -- that is T1490's domain"},
	"T1567.002": {CapabilityContainment: "containment of an exfil channel is covered by the DataProtection capability, not a separate Containment check"},
}

func techniqueFor(id string) Technique {
	switch id {
	case "T1490":
		return VSSInhibition()
	case "T1486":
		return DataEncryptedForImpact()
	case "T1567.002":
		return DataExfiltrationToCloud()
	}
	return Technique{}
}

// EvaluateStep is the integration entry point: classify, then either return
// an explicit not-tested/not-applicable row for every capability (coverage
// gap paths) or evaluate the complete applicable set for a genuine attempt.
// Never returns a partial set -- every call returns exactly 5 rows, one per
// capability, so a caller can never mistake "only 2 rows written" for "the
// other 3 don't apply".
func EvaluateStep(in StepInput, deps StepDependencies) []CapabilityResult {
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)

	if !modeled {
		return notTestedForAll(in, specificReason)
	}
	tech := techniqueFor(in.TechniqueID)
	if !isAttempt {
		return notTestedForAll(in, specificReason)
	}
	if specificReason != "" { // gate_not_confirmed / no_target_precondition / skip_unclassified
		return notTestedForAll(in, specificReason)
	}

	key := AttemptKey{RunID: in.RunID, TechniqueID: in.TechniqueID, Action: in.Action}
	out := make([]CapabilityResult, 0, 5)
	for _, cap := range allCapabilities {
		if reason, ok := notApplicable[in.TechniqueID][cap]; ok {
			out = append(out, NotApplicable(cap, tech, reason))
			continue
		}
		if undecidedApplicability[in.TechniqueID][cap] {
			// NotTested, not NotApplicable: this is an undecided "we don't
			// know yet", never a decided "no" -- using NotApplicable here
			// would wrongly set skip_reason=not_applicable, contradicting
			// the spec's own table (section B), which pins this case to
			// skip_reason=not_tested.
			out = append(out, withSpecificReason(NotTested(cap, tech, "applicability not yet decided for this (technique, capability) pair"), "applicability_undecided"))
			continue
		}
		out = append(out, evaluateApplicableCapability(cap, tech, key, deps))
	}
	return out
}

func evaluateApplicableCapability(cap Capability, tech Technique, key AttemptKey, deps StepDependencies) CapabilityResult {
	ctx := context.Background()
	switch cap {
	case CapabilityPrevention:
		ck := controlval.CorrelationKey{RunID: key.RunID, Action: key.Action}
		obs, err := deps.Prevention.Observe(ctx, ck)
		return PreventionFromValidation(tech, controlval.Evaluate(PreventionExpectationFor(tech), &obs, err))
	case CapabilityRecovery:
		result, err := deps.Recovery.ObserveSurvival(ctx, key)
		return RecoveryResultFor(tech, result, err, "")
	case CapabilityContainment:
		result, err := deps.Containment.ObserveContainment(ctx, key)
		return ContainmentResultFor(tech, result, err, "")
	case CapabilityDetection:
		tested, verified, reason, err := deps.Detection.LookupDetection(ctx, key)
		if err != nil {
			return CapabilityResult{Capability: CapabilityDetection, TechniqueID: tech.MitreID, Verdict: controlval.VerdictError, Reason: "detection lookup failed: " + err.Error()}
		}
		return DetectionFromProfileResult(tech, tested, verified, reason)
	case CapabilityDataProtection:
		status, reason, err := deps.DataProtection.LookupDataProtection(ctx, key)
		if err != nil {
			return CapabilityResult{Capability: CapabilityDataProtection, TechniqueID: tech.MitreID, Verdict: controlval.VerdictError, Reason: "data-protection lookup failed: " + err.Error()}
		}
		return DataProtectionFromDLPResult(tech, status, reason)
	}
	return CapabilityResult{}
}

func notTestedForAll(in StepInput, specificReason string) []CapabilityResult {
	tech := techniqueFor(in.TechniqueID)
	if tech.MitreID == "" {
		tech.MitreID = in.TechniqueID
	}
	out := make([]CapabilityResult, 0, 5)
	for _, cap := range allCapabilities {
		cr := NotTested(cap, tech, specificReasonText(specificReason))
		out = append(out, withSpecificReason(cr, specificReason))
	}
	return out
}

// specificReasonText renders a short code into a human-readable Reason --
// the existing CapabilityResult.Reason field stays prose; specific_reason
// (set on the persisted row by the Task 4 store, carried here as an
// unexported sidecar) is the queryable short code.
func specificReasonText(code string) string {
	switch code {
	case "technique_not_mapped":
		return "this technique has no rwevidence capability model yet"
	case "not_an_attempt":
		return "this step observes/enumerates, it does not attempt the destructive behavior"
	case "gate_not_confirmed":
		return "the scenario's own safety gate was not confirmed, so the attempt never ran"
	case "no_target_precondition":
		return "no viable target existed for the attempt to run against"
	case "skip_unclassified":
		return "the step reported skipped for a reason this integration does not yet recognize"
	case "applicability_undecided":
		return "applicability not yet decided for this (technique, capability) pair"
	}
	return code
}
```

`specificReason` needs to travel on `CapabilityResult` for Task 4's store to persist it. Modify `orchestrator/internal/rwevidence/types.go`'s `CapabilityResult` struct:

```go
type CapabilityResult struct {
	Capability  Capability
	TechniqueID string
	Verdict     controlval.Verdict
	SkipReason  controlval.SkipReason
	Reason      string
	Provenance  controlval.CorrelationKey
	// SpecificReason is a short, queryable machine code -- set only by
	// EvaluateStep's not-tested/not-applicable paths (see dispatch.go);
	// every direct capability-function call (PreventionFromValidation etc.)
	// leaves it empty, same as it always has.
	SpecificReason string
}
```

Add `withSpecificReason` to `dispatch.go`:

```go
func withSpecificReason(cr CapabilityResult, code string) CapabilityResult {
	cr.SpecificReason = code
	return cr
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestEvaluateStep -v`
Expected: PASS (6/6)

- [ ] **Step 5: Run the full package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS -- including `TestAllShippedProducers_AlwaysProduceValidCapabilityResults` (the new `SpecificReason` field doesn't affect `Valid()`, which only checks Verdict/SkipReason)

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/rwevidence/dispatch.go internal/rwevidence/dispatch_test.go internal/rwevidence/types.go
git commit -m "feat(rwevidence): EvaluateStep -- complete 5-capability evaluation for genuine attempts

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: `rw_capability_results` schema + store

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (add `CREATE TABLE IF NOT EXISTS rw_capability_results` to the existing `EnsureSchema` statement list)
- Create: `orchestrator/internal/db/rwevidence_store.go`
- Create: `orchestrator/internal/db/rwevidence_store_test.go`

**Interfaces:**
- Consumes: `rwevidence.CapabilityResult` (Task 1/3).
- Produces: `db.WriteRWCapabilityResults(ctx context.Context, pool *pgxpool.Pool, runID string, action string, results []rwevidence.CapabilityResult) error` — Task 5's dispatch call site calls this directly. `db.RWCapabilityCoverage(ctx, pool, runID string) ([]db.RWCoverageRow, error)` — Task 6 builds on this.

This test needs a real Postgres connection, same container-backed pattern as every other `internal/db` test in this codebase. Confirmed against `internal/db/tenant_test.go`: that file already declares `package db_test`, a package-level `var sharedDB *testutil.TestDB`, and the one `TestMain` allowed per package (it starts `testutil.MustSharedTestDB()`). A second `TestMain` in the same package is a compile error, so this task's test file joins `package db_test` and reuses the existing `sharedDB` var — it does not declare its own.

- [ ] **Step 1: Write the failing test for a write + read round-trip and the uniqueness/upsert behavior**

Create `orchestrator/internal/db/rwevidence_store_test.go`:

```go
package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwevidence"
)

func TestWriteRWCapabilityResults_RoundTripAndUpsertNoDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		runID := "test-run-upsert"

		results := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: controlval.VerdictFail, Reason: "allowed"},
			{Capability: rwevidence.CapabilityRecovery, TechniqueID: "T1490", Verdict: controlval.VerdictPass, Reason: "survived"},
		}
		if err := db.WriteRWCapabilityResults(ctx, pool, runID, "action-1", results); err != nil {
			t.Fatalf("first write: %v", err)
		}

		rows, err := db.RWCapabilityCoverage(ctx, pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		// Retry: same run/action/capability -- must overwrite, not duplicate.
		retried := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: controlval.VerdictPass, Reason: "blocked on retry"},
		}
		if err := db.WriteRWCapabilityResults(ctx, pool, runID, "action-1", retried); err != nil {
			t.Fatalf("retry write: %v", err)
		}
		rows, err = db.RWCapabilityCoverage(ctx, pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("after retry, got %d rows, want 2 (upsert, not a duplicate)", len(rows))
		}
	})
}

func TestWriteRWCapabilityResults_RejectsInvalidSkipPair(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		bad := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: controlval.VerdictFail, SkipReason: controlval.SkipInsufficientEvidence},
		}
		if err := db.WriteRWCapabilityResults(context.Background(), pool, "test-run-invalid", "action-1", bad); err == nil {
			t.Fatal("expected an error -- FAIL must never carry a SkipReason, application code must reject this before it reaches the DB")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/db/ -run TestWriteRWCapabilityResults -v`
Expected: FAIL — `undefined: WriteRWCapabilityResults`, `undefined: RWCapabilityCoverage` (compile error)

- [ ] **Step 3: Add the table to `EnsureSchema` and implement the store**

In `orchestrator/internal/db/postgres.go`, add to the statement list inside `EnsureSchema` (alongside the other `CREATE TABLE IF NOT EXISTS` entries, e.g. right after `execution_attempts` around line 1834):

```go
`CREATE TABLE IF NOT EXISTS rw_capability_results (
	id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
	run_id          text        NOT NULL,
	action          text        NOT NULL,
	technique_id    text        NOT NULL,
	capability      text        NOT NULL,
	verdict         text        NOT NULL CHECK (verdict IN ('PASS','FAIL','ERROR','SKIPPED')),
	skip_reason     text        CHECK (skip_reason IN ('insufficient_evidence','not_applicable','not_tested')),
	specific_reason text        NOT NULL DEFAULT '',
	reason          text        NOT NULL DEFAULT '',
	simulated       boolean     NOT NULL DEFAULT true,
	provenance      jsonb,
	created_at      timestamptz NOT NULL DEFAULT NOW(),

	CONSTRAINT rw_capres_skip_ck CHECK (
		(verdict = 'SKIPPED' AND skip_reason IS NOT NULL) OR
		(verdict <> 'SKIPPED' AND skip_reason IS NULL)),
	CONSTRAINT rw_capres_identity UNIQUE (run_id, action, capability)
)`,
```

Create `orchestrator/internal/db/rwevidence_store.go`:

```go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/rwevidence"
)

// WriteRWCapabilityResults persists one step's complete capability-result
// set (always len 5, see rwevidence.EvaluateStep) as an upsert keyed on
// (run_id, action, capability) -- a retry of the same step overwrites its
// own prior rows rather than duplicating them. Every result is validated
// via CapabilityResult.Valid() before any write is attempted: the DB's own
// CHECK constraint is a backstop, not the primary enforcement point, so a
// caller gets a clear application-level error rather than a raw SQL
// constraint violation. simulated is always written true -- no caller of
// this function in this sub-project can pass false (there is no parameter
// for it). Wrapped in a transaction (same Begin/Rollback/Commit idiom as
// internal/api/enroll_csr_handlers.go's CSR issuance, the only existing
// precedent for a multi-statement write in this codebase) so a failure on
// row 3 of 5 rolls back rows 1-2 -- this is what makes "never represent
// partial coverage" (spec section F) actually true rather than aspirational.
func WriteRWCapabilityResults(ctx context.Context, pool *pgxpool.Pool, runID, action string, results []rwevidence.CapabilityResult) error {
	for _, r := range results {
		if err := r.Valid(); err != nil {
			return fmt.Errorf("rw_capability_results: refusing to write invalid result for %s/%s: %w", r.Capability, r.TechniqueID, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rw_capability_results: begin tx for run=%s action=%s: %w", runID, action, err)
	}
	defer tx.Rollback(ctx)

	for _, r := range results {
		var skipReason *string
		if r.SkipReason != "" {
			s := string(r.SkipReason)
			skipReason = &s
		}
		var provenance []byte
		if r.Provenance != (controlval.CorrelationKey{}) {
			provenance, _ = json.Marshal(r.Provenance)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO rw_capability_results
				(run_id, action, technique_id, capability, verdict, skip_reason, specific_reason, reason, provenance)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (run_id, action, capability) DO UPDATE SET
				technique_id = EXCLUDED.technique_id,
				verdict = EXCLUDED.verdict,
				skip_reason = EXCLUDED.skip_reason,
				specific_reason = EXCLUDED.specific_reason,
				reason = EXCLUDED.reason,
				provenance = EXCLUDED.provenance,
				created_at = NOW()`,
			runID, action, r.TechniqueID, string(r.Capability), string(r.Verdict), skipReason, r.SpecificReason, r.Reason, provenance)
		if err != nil {
			return fmt.Errorf("rw_capability_results: write failed for run=%s action=%s capability=%s: %w", runID, action, r.Capability, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("rw_capability_results: commit for run=%s action=%s: %w", runID, action, err)
	}
	return nil
}
```

Add `RWCapabilityCoverage` to the same file:

```go
// RWCoverageRow is one (technique, capability, verdict, skip_reason,
// specific_reason) group for a run -- Task 6 builds the full coverage
// query from this.
type RWCoverageRow struct {
	TechniqueID    string
	Capability     string
	Verdict        string
	SkipReason     string
	SpecificReason string
	Count          int
}

func RWCapabilityCoverage(ctx context.Context, pool *pgxpool.Pool, runID string) ([]RWCoverageRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT technique_id, capability, verdict, COALESCE(skip_reason, ''), specific_reason, COUNT(*)
		FROM rw_capability_results
		WHERE run_id = $1
		GROUP BY technique_id, capability, verdict, skip_reason, specific_reason`, runID)
	if err != nil {
		return nil, fmt.Errorf("rw_capability_results coverage query failed for run=%s: %w", runID, err)
	}
	defer rows.Close()
	var out []RWCoverageRow
	for rows.Next() {
		var r RWCoverageRow
		if err := rows.Scan(&r.TechniqueID, &r.Capability, &r.Verdict, &r.SkipReason, &r.SpecificReason, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/db/ -run TestWriteRWCapabilityResults -v`
Expected: PASS (2/2)

- [ ] **Step 5: Run the full db package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/db/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/db/postgres.go internal/db/rwevidence_store.go internal/db/rwevidence_store_test.go
git commit -m "feat(db): rw_capability_results table + WriteRWCapabilityResults/RWCapabilityCoverage

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Dispatch call site + failure visibility

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (the call site at `scenario.Interpret(step, execResult)`, around line 2859)
- Test: `orchestrator/internal/api/rwevidence_dispatch_test.go` (new)

**Interfaces:**
- Consumes: `rwevidence.EvaluateStep`, `rwevidence.StepInput`, `rwevidence.StepDependencies` (Task 3); `db.WriteRWCapabilityResults` (Task 4); `scenario.TaskID` (existing).
- Produces: nothing new for later tasks — this is the integration point itself.

- [ ] **Step 1: Write the failing test proving a dispatched T1490 step produces a persisted row and the legacy outcome is untouched**

Confirmed against the real, established pattern in `internal/api/submit_scenario_result_test.go` and `internal/api/result_ingestion_helpers_test.go`: this package already has `sharedDB *testutil.TestDB` + `TestMain` (`internal/api/testmain_test.go` — do not add a second one), `seedRunRow(t, pool, runID, scenarioID, agentID, status)` (seeds both the agent and the `scenario_runs` row), and `submitResultOK(t, h, scenario.RawRunResult{...})` (POSTs through the real `h.SubmitScenarioResult` handler and asserts 200). This task reuses all three rather than inventing new ones.

Create `orchestrator/internal/api/rwevidence_dispatch_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestSubmitScenarioResult_WritesRWCapabilityResultsAlongsideLegacyOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rw-dispatch-run"
		seedRunRow(t, pool, runID, "sc-rw-dispatch", "agent-rw-dispatch", "running")

		stepName := "VSS Shadow Copy Deletion (lab - requires BAS_CONFIRM_VSS_DELETE=true)"
		taskID := scenario.TaskID("T1490", stepName)

		// seedRunRow's scenario_id ("sc-rw-dispatch") has no YAML backing in
		// this test's temp-dir engine, so handlers.go's stepMap would stay
		// empty via the sc.Steps path. Real dispatch overlays stepMap from
		// scenario_runs.step_meta for exactly this case (dynamically-built
		// ART/Caldera steps -- handlers.go ~2804-2819); seeding it directly
		// is the same mechanism a real dispatch would have populated, not a
		// shortcut around it.
		meta := map[string]scenario.StepMeta{
			taskID: {TechniqueID: "T1490", Name: stepName, Framework: "custom"},
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`, metaJSON, runID); err != nil {
			t.Fatalf("seed step_meta: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "sc-rw-dispatch", AgentID: "agent-rw-dispatch",
			Results: []scenario.ExecResult{{
				TaskID: taskID, ExitCode: 0,
				Stdout: "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true' - VSS deletion skipped (default-disabled per ransm safety policy).",
			}},
		})

		rows, err := db.RWCapabilityCoverage(context.Background(), pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 5 {
			t.Fatalf("got %d rw_capability_results rows, want 5 (one per capability)", len(rows))
		}
		for _, r := range rows {
			if r.SpecificReason != "gate_not_confirmed" {
				t.Errorf("%s: specificReason = %q, want gate_not_confirmed", r.Capability, r.SpecificReason)
			}
			if r.Verdict != "SKIPPED" {
				t.Errorf("%s: verdict = %q, want SKIPPED -- a gate-skipped attempt must never produce PASS", r.Capability, r.Verdict)
			}
		}

		// The legacy outcome is unaffected by any of this. readRunResults
		// (result_ingestion_helpers_test.go) decodes the persisted
		// []models.SimulationResult the same way submit_scenario_result_test.go
		// already does.
		results := readRunResults(t, pool, runID)
		if len(results) != 1 || string(results[0].Result) != "skipped" {
			t.Fatalf("legacy results = %+v, want exactly one skipped result (unchanged by this integration)", results)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestSubmitScenarioResult_WritesRWCapabilityResultsAlongsideLegacyOutcome -v`
Expected: FAIL — 0 rows in `rw_capability_results` (the integration isn't wired yet)

- [ ] **Step 3: Wire `EvaluateStep` into the call site**

In `orchestrator/internal/api/handlers.go`, modify the loop around line 2854-2860:

```go
} else {
	simResults = make([]models.SimulationResult, 0, len(raw.Results))
	for _, execResult := range raw.Results {
		step, found := stepMap[execResult.TaskID]
		if !found {
			step = scenario.Step{Framework: "custom"}
		}
		simResults = append(simResults, scenario.Interpret(step, execResult))
	}
}
```

to:

```go
} else {
	simResults = make([]models.SimulationResult, 0, len(raw.Results))
	for _, execResult := range raw.Results {
		step, found := stepMap[execResult.TaskID]
		if !found {
			step = scenario.Step{Framework: "custom"}
		}
		sim := scenario.Interpret(step, execResult)
		simResults = append(simResults, sim)
		h.recordRWEvidence(r.Context(), raw.RunID, step, sim)
	}
}
```

Add `recordRWEvidence` as a new method, near the bottom of `handlers.go` or in its own small file `orchestrator/internal/api/rwevidence_dispatch.go`:

```go
package api

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
)

// recordRWEvidence is additive and best-effort toward scoring (there is no
// scoring yet to feed), but never silent about failure: a write error is
// logged, never swallowed, and never allowed to touch sim/the caller's
// legacy result in any way. All observers are fakes in this sub-project --
// T1/T2 real-observer wiring is a later, separate piece of work.
func (h *Handler) recordRWEvidence(ctx context.Context, runID string, step scenario.Step, sim models.SimulationResult) {
	in := rwevidence.StepInput{
		RunID:       runID,
		Action:      scenario.TaskID(step.TechniqueID, step.Name),
		TechniqueID: models.NormalizeID(step.TechniqueID),
		StepName:    step.Name,
		CheckResult: string(sim.Result),
		Details:     sim.Details + " " + sim.RawOutput,
	}
	deps := rwevidence.StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &rwevidence.FakeRecoveryObserver{},
		Containment:    &rwevidence.FakeContainmentObserver{},
		Detection:      &rwevidence.FakeDetectionLookup{},
		DataProtection: &rwevidence.FakeDataProtectionLookup{},
	}
	results := rwevidence.EvaluateStep(in, deps)
	if err := db.WriteRWCapabilityResults(ctx, h.db, runID, in.Action, results); err != nil {
		// Handler has no structured logger -- this codebase's existing idiom
		// throughout handlers.go is stdlib log.Printf with a bracketed tag
		// (e.g. "[phase0b] insert execution_attempt for run %s: %v", line 1497),
		// matched here rather than inventing a logging dependency this package
		// doesn't have.
		log.Printf("[rwevidence] rw_capability_results write failed for run %s action %s technique %s: %v", runID, in.Action, in.TechniqueID, err)
	}
}
```

Add `"log"` to this file's imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestSubmitScenarioResult_WritesRWCapabilityResultsAlongsideLegacyOutcome -v`
Expected: PASS

- [ ] **Step 5: Write and run the failure-visibility test**

Add to `orchestrator/internal/api/rwevidence_dispatch_test.go`. This must not close or otherwise damage `sharedDB`'s pool -- it is shared across every test in this package's binary (`testutil.MustSharedTestDB`'s own doc comment: "a container meant to be reused by every test in a package's test binary"), so closing it would break every test that runs after this one in the same `go test` invocation. An already-cancelled context is a safe, realistic way to force every DB call in this path to fail (the same failure class a real request timeout or client disconnect produces) without touching shared infrastructure:

```go
func TestRecordRWEvidence_WriteFailureIsLoggedNotSwallowedAndNeverTouchesLegacyResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rw-dispatch-failure-run"
		seedRunRow(t, pool, runID, "sc-rw-dispatch-failure", "agent-rw-dispatch-failure", "running")

		step := scenario.Step{TechniqueID: "T1490", Name: "VSS Shadow Copy Deletion via WMI", Framework: "custom"}
		execResult := scenario.ExecResult{TaskID: scenario.TaskID(step.TechniqueID, step.Name), ExitCode: 1, Stdout: "FAIL: deleted 1 shadow copy"}
		sim := scenario.Interpret(step, execResult)

		cancelled, cancel := context.WithCancel(context.Background())
		cancel() // already cancelled -- every subsequent pool operation in this ctx fails

		h.recordRWEvidence(cancelled, runID, step, sim) // must not panic, must not propagate the error to its caller

		// A fresh, un-cancelled context against the same (undamaged) shared
		// pool confirms nothing was written -- never a partial set.
		rows, err := db.RWCapabilityCoverage(context.Background(), pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("got %d rows after a forced write failure, want 0 -- a failed write must never leave a partial set behind", len(rows))
		}
	})
}
```

Run: `cd orchestrator && go test ./internal/api/ -run TestRecordRWEvidence_WriteFailureIsLoggedNotSwallowedAndNeverTouchesLegacyResult -v`
Expected: PASS

- [ ] **Step 6: Run the full api package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/api/ -v 2>&1 | tail -50`
Expected: PASS (existing `submit_scenario_result_test.go` and friends unaffected -- `recordRWEvidence` never touches `simResults`/the legacy write path)

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/handlers.go internal/api/rwevidence_dispatch.go internal/api/rwevidence_dispatch_test.go
git commit -m "feat(api): wire rwevidence.EvaluateStep into the real scenario-result dispatch path

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: Coverage-accounting query surface

**Files:**
- Modify: `orchestrator/internal/db/rwevidence_store.go` (add a summarizing helper on top of `RWCapabilityCoverage`)
- Modify: `orchestrator/internal/db/rwevidence_store_test.go`

**Interfaces:**
- Consumes: `RWCapabilityCoverage`, `RWCoverageRow` (Task 4).
- Produces: `db.RWCoverageSummary{Evaluated, NotApplicable, NotTestedByReason map[string]int} ` and `db.SummarizeRWCoverage(rows []RWCoverageRow) RWCoverageSummary` -- a later sub-project's UI/scoring work reads this, not built here.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/db/rwevidence_store_test.go` (package `db_test`, so this references the `db.` prefix like every other function in this file):

```go
func TestSummarizeRWCoverage_DistinguishesEvaluatedNotApplicableAndNotTestedReasons(t *testing.T) {
	rows := []db.RWCoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 3},
		{Capability: "recovery", Verdict: "FAIL", Count: 1},
		{Capability: "containment", Verdict: "SKIPPED", SkipReason: "not_applicable", Count: 2},
		{Capability: "data_protection", Verdict: "SKIPPED", SkipReason: "not_tested", SpecificReason: "technique_not_mapped", Count: 10},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "not_tested", SpecificReason: "gate_not_confirmed", Count: 1},
	}
	s := db.SummarizeRWCoverage(rows)
	if s.Evaluated != 4 { // PASS(3) + FAIL(1)
		t.Errorf("evaluated = %d, want 4", s.Evaluated)
	}
	if s.NotApplicable != 2 {
		t.Errorf("notApplicable = %d, want 2", s.NotApplicable)
	}
	if s.NotTestedByReason["technique_not_mapped"] != 10 {
		t.Errorf("not_tested/technique_not_mapped = %d, want 10", s.NotTestedByReason["technique_not_mapped"])
	}
	if s.NotTestedByReason["gate_not_confirmed"] != 1 {
		t.Errorf("not_tested/gate_not_confirmed = %d, want 1", s.NotTestedByReason["gate_not_confirmed"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/db/ -run TestSummarizeRWCoverage -v`
Expected: FAIL — `undefined: SummarizeRWCoverage`

- [ ] **Step 3: Implement it**

Append to `orchestrator/internal/db/rwevidence_store.go`:

```go
// RWCoverageSummary distinguishes a technique-level coverage gap from an
// individual capability evaluation gap, per the spec's coverage-accounting
// requirement. Evaluated counts every row whose evaluator actually ran
// (PASS/FAIL/ERROR, or SKIPPED/insufficient_evidence -- the evaluator ran
// and came back ambiguous, which is still "evaluated", not "not tested").
type RWCoverageSummary struct {
	Evaluated         int
	NotApplicable     int
	NotTestedByReason map[string]int
}

func SummarizeRWCoverage(rows []RWCoverageRow) RWCoverageSummary {
	s := RWCoverageSummary{NotTestedByReason: map[string]int{}}
	for _, r := range rows {
		switch {
		case r.Verdict != "SKIPPED":
			s.Evaluated += r.Count
		case r.SkipReason == "insufficient_evidence":
			s.Evaluated += r.Count
		case r.SkipReason == "not_applicable":
			s.NotApplicable += r.Count
		case r.SkipReason == "not_tested":
			s.NotTestedByReason[r.SpecificReason] += r.Count
		}
	}
	return s
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/ -run TestSummarizeRWCoverage -v`
Expected: PASS

- [ ] **Step 5: Run the full db package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/db/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/db/rwevidence_store.go internal/db/rwevidence_store_test.go
git commit -m "feat(db): SummarizeRWCoverage -- evaluated/not-applicable/not-tested-by-reason breakdown

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 7: Real-content acceptance tests (the actual exit criterion)

**Files:**
- Create: `orchestrator/internal/rwevidence/realcorpus_test.go`

**Interfaces:**
- Consumes: `EvaluateStep`, `StepInput`, `classifyRansomwareStep` (Tasks 2-3); reads the real YAML files directly off disk.
- Produces: nothing — this is the plan's terminal verification layer, proving the spec's 11 acceptance criteria against the actual 8 scenario files, not synthetic fixtures.

This task does not touch the DB or the API package -- it drives `rwevidence.EvaluateStep` directly against every technique-tagged step `scenario.ParseYAML` (`internal/scenario/engine.go:274`, confirmed the real parser during planning) produces for all 8 files, with fakes standing in for every observer.

- [ ] **Step 1: Write the full-corpus enumeration test (acceptance criteria 1-2)**

Create `orchestrator/internal/rwevidence/realcorpus_test.go`:

```go
package rwevidence

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
}

// repoScenariosDir resolves ../../../scenarios relative to this package,
// same relative path adcoverage's real-corpus test already uses
// successfully (internal/adcoverage/index_test.go) -- reused, not
// reinvented.
func repoScenariosDir(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

func loadRealSteps(t *testing.T, filename string) []scenario.Step {
	// scenario.ParseYAML (internal/scenario/engine.go:274) takes raw bytes
	// and returns *Scenario{..., Steps []Step}; confirmed against the real
	// function during planning rather than assumed.
	b, err := os.ReadFile(filepath.Join(repoScenariosDir(t), filename))
	if err != nil {
		t.Fatalf("%s: %v", filename, err)
	}
	sc, err := scenario.ParseYAML(b)
	if err != nil {
		t.Fatalf("%s: %v", filename, err)
	}
	return sc.Steps
}

func TestRealCorpus_EveryTechniqueTaggedStepIsAccountedFor(t *testing.T) {
	for _, file := range ransomwareScenarioFiles {
		steps := loadRealSteps(t, file)
		for _, step := range steps {
			if step.TechniqueID == "" {
				continue // not every step is technique-tagged (e.g. check_id-only posture checks)
			}
			in := StepInput{RunID: "corpus-test", Action: scenario.TaskID(step.TechniqueID, step.Name), TechniqueID: step.TechniqueID, StepName: step.Name, CheckResult: "fail"}
			// &controlval.FakeProvider{} (nil Obs/Err maps) is safe -- nil-map
			// lookups in Go return the zero value with ok=false, so Observe
			// returns Observation{}, nil for any key. Confirmed against
			// controlval/provider.go rather than assumed.
			results := EvaluateStep(in, StepDependencies{Prevention: &controlval.FakeProvider{}, Recovery: &FakeRecoveryObserver{}, Containment: &FakeContainmentObserver{}, Detection: &FakeDetectionLookup{}, DataProtection: &FakeDataProtectionLookup{}})
			if len(results) != 5 {
				t.Errorf("%s / %q (technique %s): got %d results, want 5 -- every technique-tagged step must be fully accounted for", file, step.Name, step.TechniqueID, len(results))
			}
		}
	}
}
```

Add `"github.com/audspect/bas/internal/controlval"` to this file's imports.

- [ ] **Step 2: Run test to verify it fails or passes for the right reason**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestRealCorpus_EveryTechniqueTaggedStepIsAccountedFor -v`
Expected: either PASS immediately (Tasks 2-3 already made `EvaluateStep` total — every branch returns exactly 5 results) or FAIL naming the exact file/step/technique combination that doesn't, which is itself useful information: if it fails, read the failure and fix `classifyRansomwareStep`/`EvaluateStep`, don't change the test to accept fewer than 5.

- [ ] **Step 3: Write and run the em-07 three-independent-actions test (acceptance criterion 3)**

Add to `orchestrator/internal/rwevidence/realcorpus_test.go`:

```go
func TestRealCorpus_EM07ThreeT1490StepsStayIndependent(t *testing.T) {
	steps := loadRealSteps(t, "endpoint-mastery/em-07-ransomware-readiness.yaml")
	var t1490Steps []scenario.Step
	for _, s := range steps {
		if s.TechniqueID == "T1490" {
			t1490Steps = append(t1490Steps, s)
		}
	}
	if len(t1490Steps) != 3 {
		t.Fatalf("got %d T1490 steps in em-07, want 3 (shadow-copy deletion, wbadmin catalog delete, bcdedit disable)", len(t1490Steps))
	}

	recoveryObs := &FakeRecoveryObserver{Results: map[string]SurvivalResult{}}
	actions := make([]string, 3)
	for i, s := range t1490Steps {
		actions[i] = scenario.TaskID(s.TechniqueID, s.Name)
		recoveryObs.Results[recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: actions[i]})] = []SurvivalResult{SurvivalConfirmed, SurvivalLost, SurvivalIndeterminate}[i]
	}
	if actions[0] == actions[1] || actions[1] == actions[2] || actions[0] == actions[2] {
		t.Fatalf("em-07's three T1490 steps produced colliding action IDs: %v -- dedupeStepIdentity should have prevented this", actions)
	}

	for i, s := range t1490Steps {
		in := StepInput{RunID: "r1", Action: actions[i], TechniqueID: s.TechniqueID, StepName: s.Name, CheckResult: "fail"}
		deps := StepDependencies{Prevention: &controlval.FakeProvider{}, Recovery: recoveryObs, Containment: &FakeContainmentObserver{}, Detection: &FakeDetectionLookup{}, DataProtection: &FakeDataProtectionLookup{}}
		results := EvaluateStep(in, deps)
		var recovery CapabilityResult
		for _, r := range results {
			if r.Capability == CapabilityRecovery {
				recovery = r
			}
		}
		want := []controlval.Verdict{controlval.VerdictPass, controlval.VerdictFail, controlval.VerdictSkipped}[i]
		if recovery.Verdict != want {
			t.Errorf("step %q: recovery verdict = %q, want %q -- the three actions must not collapse into one shared result", s.Name, recovery.Verdict, want)
		}
	}
}
```

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestRealCorpus_EM07ThreeT1490StepsStayIndependent -v`
Expected: PASS (needs `"github.com/audspect/bas/internal/controlval"` added to this file's imports)

- [ ] **Step 4: Write and run the akira two-skip-pattern test (acceptance criterion 4)**

Add to `orchestrator/internal/rwevidence/realcorpus_test.go`:

```go
func TestRealCorpus_AkiraTwoDistinctT1490SkipPatterns(t *testing.T) {
	steps := loadRealSteps(t, "akira-kill-chain.yaml")
	var deletionStep scenario.Step
	for _, s := range steps {
		if s.TechniqueID == "T1490" && s.Name != "" && !reconnaissanceStepNames[s.Name] {
			deletionStep = s
		}
	}
	if deletionStep.Name == "" {
		t.Fatal("expected to find Akira's VSS shadow-copy-deletion step")
	}

	gateIn := StepInput{TechniqueID: "T1490", StepName: deletionStep.Name, CheckResult: "skipped",
		Details: "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true' - WMI-based VSS deletion skipped (default-disabled per ransomware safety policy)."}
	_, _, gateReason := classifyRansomwareStep(gateIn)
	if gateReason != "gate_not_confirmed" {
		t.Errorf("gate-skip case: specificReason = %q, want gate_not_confirmed", gateReason)
	}

	targetIn := StepInput{TechniqueID: "T1490", StepName: deletionStep.Name, CheckResult: "skipped",
		Details: "SKIP: no C: VSS shadow copies exist - nothing to delete. Create a snapshot first with: vssadmin create shadow /for=C:"}
	_, _, targetReason := classifyRansomwareStep(targetIn)
	if targetReason != "no_target_precondition" {
		t.Errorf("no-target case: specificReason = %q, want no_target_precondition", targetReason)
	}
	if gateReason == targetReason {
		t.Fatal("two genuinely different skip reasons on the same real step must not classify identically")
	}
}
```

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestRealCorpus_AkiraTwoDistinctT1490SkipPatterns -v`
Expected: PASS

- [ ] **Step 5: Add `controlval` import, run the full realcorpus file, then the full package**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run TestRealCorpus -v`
Expected: PASS (3/3)

Run: `cd orchestrator && go test ./internal/rwevidence/ ./internal/db/ ./internal/api/ -v 2>&1 | tail -80`
Expected: PASS across all three packages — this is the plan's full regression gate

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/rwevidence/realcorpus_test.go
git commit -m "test(rwevidence): pin EvaluateStep against the real 8-scenario ransomware corpus

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```
