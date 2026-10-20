# Cross-Module Propagation Join Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/rwpropagation`, a pure-Go package that joins AD-mastery graph reachability (`admatrix`), lateral-movement evidence (`latmove`), and ransomware-payload containment evidence (`rwevidence`, via `db.RWAttemptRow`) into one provenance-preserving report for a single simulated propagation incident.

**Architecture:** One new package, two files (`types.go`, `correlate.go`), zero new persistence, zero HTTP surface, zero testcontainers. `BuildReport(Input) Report` is the single entry point; it never returns an error — every "something was off" case (missing correlation, an instrumentation gap, an inapplicable capability) is a value in the result.

**Tech Stack:** Go. Consumes types from `internal/admatrix`, `internal/adprimitive`, `internal/latmove`, `internal/controlval`, `internal/db` — imported for their types only, never called.

**Spec:** `docs/superpowers/specs/2026-10-12-cross-module-propagation-join-design.md`

## Global Constraints

- `TimeToIsolate` is always `TimeToIsolateNotEstablishable`, regardless of input shape — never computed from any timestamp present anywhere in the input or report.
- The `"ad"` and `"lateral_movement"` `LegContainment` entries are **always** `ContainmentNoObserver` with an empty `Containment` slice. This is hardcoded, never computed from input data — there is no field anywhere in `Input` through which AD or lateral-movement containment evidence could flow, even if a caller tried to supply it.
- `Correlation` flips to `CorrelationUncorrelated` the moment `len(Exclusions) > 0` for *any* reason — one mismatched item taints the whole report's correlation claim, even though every correctly-tagged item still survives in its typed slice.
- A leg with zero supplied-but-correctly-tagged items is `CorrelationEstablished`, never treated as an exclusion. "Nothing was supplied" and "something was supplied but didn't match" must stay visibly different.
- `BuildReport` never returns an `error` — every outcome, including total correlation failure, is a value inside `Report`.
- A technique's containment `Status`/`Verdict` must never be read as representing a different technique's evidence. `T1486` evaluated, `T1490` not-applicable, and `T1560.001` not-instrumented must coexist in the same `Containment` slice with zero cross-influence.
- Duplicate containment rows for the same technique resolve by earliest `CreatedAt`; ties resolve by lexicographically-smallest `Action` — deterministic, never dependent on input slice order.
- This package makes zero database or HTTP calls. It imports `internal/db` only for the `RWAttemptRow` type (mirroring `internal/rwresponse`'s identical precedent).

## Review Focus

- **Reintroducing the exact gap the user caught during spec review.** The single easiest mistake: letting one technique's containment row (e.g. `T1486` PASS) leak into another technique's entry (e.g. `T1490`), or collapsing multiple techniques into one summary value. Task 1's `TestBuildReport_MultiTechniqueContainmentIndependence` pins this directly — it is the most important test in this plan.
- **A same-`CreatedAt` tie silently depending on input order.** `sort.Slice` is not stable by default across equal keys unless the comparator itself breaks every tie deterministically. Task 1's tiebreak test constructs two rows with an *identical* `CreatedAt` and asserts the lexicographically-smaller `Action` wins regardless of which one appears first in the slice.
- **Letting AD/lateral-movement evidence leak into containment.** Supplying `ADReachability`/`LateralMovementExecution` evidence must never change the `"ad"` or `"lateral_movement"` legs' `ContainmentNoObserver` status — there is no code path that could legitimately do this, but a careless refactor could add one. Task 1 pins it directly with evidence present on both legs.
- **Confusing "not applicable" with "not instrumented."** A `SKIPPED`/`not_applicable` row and a complete absence of any containment row for a technique are semantically different (a decided "no" vs. an honest gap) — Task 1's multi-technique test exercises both in the same report.
- **A single mismatched item destroying the whole report's evidence, not just its correlation claim.** `CorrelationUncorrelated` must not mean "every slice is now empty" — Task 1's partial-survival test asserts the correctly-tagged item is still present and correct even though the report is flagged uncorrelated.

---

### Task 1: Core types and `BuildReport`

**Files:**
- Create: `orchestrator/internal/rwpropagation/types.go`
- Create: `orchestrator/internal/rwpropagation/correlate.go`
- Create: `orchestrator/internal/rwpropagation/correlate_test.go`

**Interfaces:**
- Consumes: `admatrix.SimResult`, `admatrix.ValidationLevel`, `admatrix.LevelModelSimulated` (`internal/admatrix/matrix.go`); `adprimitive.Capability`, `adprimitive.Primitive` (`internal/adprimitive/types.go`); `latmove.Technique`, `latmove.AccessCondition` (`AccessGranted`/`AccessDenied`/`AccessUnknown`), `latmove.AttemptKey`, `latmove.AttemptResult` (`ResultExecuted`/`ResultAccessDenied`/`ResultIndeterminate`) (`internal/latmove/technique.go`, `discovery.go`, `observation.go`); `controlval.Verdict`, `controlval.VerdictSkipped`, `controlval.SkipReason`, `controlval.SkipNotApplicable` (`internal/controlval/controlval.go`); `db.RWAttemptRow{TechniqueID, Action, Capability string, Verdict controlval.Verdict, SkipReason controlval.SkipReason, Reason string, CreatedAt time.Time}` (`internal/db/rwevidence_store.go`, added as sub-project #5's Task 4 — note it has **no `RunID` field**).
- Produces: `AssessmentContext`, `ADReachability`, `LateralMovementAccess`, `LateralMovementExecution`, `TechniqueContainmentStatus` (+3 consts), `RansomwareContainment`, `ContainmentAvailability` (+2 consts), `LegContainment`, `TimeToIsolateStatus` (+1 const) from `types.go`; `TaggedADReachability`, `TaggedLateralMovementAccess`, `TaggedLateralMovementExecution`, `Input`, `Exclusion`, `CorrelationStatus` (+2 consts), `Report`, `BuildReport(Input) Report` from `correlate.go` — all consumed by Task 2.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwpropagation/correlate_test.go`:

```go
package rwpropagation

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/latmove"
)

const testAssessmentID = "assess-1"

func baseContext() AssessmentContext {
	return AssessmentContext{AssessmentID: testAssessmentID, RunID: "run-1"}
}

func containmentRow(techniqueID, capability, action string, verdict controlval.Verdict, skipReason controlval.SkipReason, createdAt time.Time) db.RWAttemptRow {
	return db.RWAttemptRow{TechniqueID: techniqueID, Action: action, Capability: capability, Verdict: verdict, SkipReason: skipReason, CreatedAt: createdAt}
}

func findLeg(t *testing.T, report Report, leg string) LegContainment {
	t.Helper()
	for _, lc := range report.Containment {
		if lc.Leg == leg {
			return lc
		}
	}
	t.Fatalf("leg %s not found", leg)
	return LegContainment{}
}

func findContainment(t *testing.T, report Report, techniqueID string) RansomwareContainment {
	t.Helper()
	leg := findLeg(t, report, "ransomware_payload")
	for _, c := range leg.Containment {
		if c.TechniqueID == techniqueID {
			return c
		}
	}
	t.Fatalf("no containment entry found for technique %s", techniqueID)
	return RansomwareContainment{}
}

func TestBuildReport_ADReachabilityLevelStaysModelSimulated(t *testing.T) {
	input := Input{
		Context: baseContext(),
		ADReachability: []TaggedADReachability{
			{AssessmentID: testAssessmentID, Result: admatrix.SimResult{
				Target:    adprimitive.Capability{Kind: adprimitive.CapLocalAdmin, Target: "SERVER01"},
				Reachable: true,
				Level:     admatrix.LevelModelSimulated,
			}},
		},
	}
	report := BuildReport(input)
	if len(report.ADReachability) != 1 {
		t.Fatalf("got %d AD reachability entries, want 1", len(report.ADReachability))
	}
	if report.ADReachability[0].Level != admatrix.LevelModelSimulated {
		t.Errorf("Level = %v, want LevelModelSimulated", report.ADReachability[0].Level)
	}
}

func TestBuildReport_LateralMovementConditionNeverCollapsedToBool(t *testing.T) {
	input := Input{
		Context: baseContext(),
		LateralMovementAccess: []TaggedLateralMovementAccess{
			{AssessmentID: testAssessmentID, Technique: latmove.WMIRemoteProcessCreation(), Principal: "user1", Destination: "host1", Condition: latmove.AccessUnknown},
		},
	}
	report := BuildReport(input)
	if len(report.LateralMovementAccess) != 1 {
		t.Fatalf("got %d lateral movement access entries, want 1", len(report.LateralMovementAccess))
	}
	if report.LateralMovementAccess[0].Condition != latmove.AccessUnknown {
		t.Errorf("Condition = %q, want AccessUnknown -- never collapsed to a bool", report.LateralMovementAccess[0].Condition)
	}
}

func TestBuildReport_ADDeniedAndLateralMovementDeniedDoNotInfluenceEachOther(t *testing.T) {
	input := Input{
		Context: baseContext(),
		ADReachability: []TaggedADReachability{
			{AssessmentID: testAssessmentID, Result: admatrix.SimResult{
				Target: adprimitive.Capability{Kind: adprimitive.CapLocalAdmin, Target: "DC01"}, Reachable: false, Level: admatrix.LevelModelSimulated,
			}},
		},
		LateralMovementAccess: []TaggedLateralMovementAccess{
			{AssessmentID: testAssessmentID, Technique: latmove.WMIRemoteProcessCreation(), Principal: "user1", Destination: "host1", Condition: latmove.AccessDenied},
		},
	}
	report := BuildReport(input)
	if report.ADReachability[0].Reachable != false {
		t.Errorf("AD Reachable = %v, want false", report.ADReachability[0].Reachable)
	}
	if report.LateralMovementAccess[0].Condition != latmove.AccessDenied {
		t.Errorf("lateral movement Condition = %q, want AccessDenied", report.LateralMovementAccess[0].Condition)
	}
}

func TestBuildReport_AlwaysExactlyThreeLegContainmentEntriesInFixedOrder(t *testing.T) {
	report := BuildReport(Input{Context: baseContext()})
	if len(report.Containment) != 3 {
		t.Fatalf("got %d LegContainment entries, want 3", len(report.Containment))
	}
	wantLegs := []string{"ad", "lateral_movement", "ransomware_payload"}
	for i, want := range wantLegs {
		if report.Containment[i].Leg != want {
			t.Errorf("Containment[%d].Leg = %q, want %q", i, report.Containment[i].Leg, want)
		}
	}
}

func TestBuildReport_ADAndLateralMovementLegsAlwaysNoObserverEvenWithEvidenceSupplied(t *testing.T) {
	input := Input{
		Context: baseContext(),
		ADReachability: []TaggedADReachability{
			{AssessmentID: testAssessmentID, Result: admatrix.SimResult{Reachable: true, Level: admatrix.LevelModelSimulated}},
		},
		LateralMovementExecution: []TaggedLateralMovementExecution{
			{AssessmentID: testAssessmentID, Result: latmove.ResultExecuted},
		},
	}
	report := BuildReport(input)
	for _, leg := range []string{"ad", "lateral_movement"} {
		lc := findLeg(t, report, leg)
		if lc.Availability != ContainmentNoObserver {
			t.Errorf("leg %s Availability = %q, want ContainmentNoObserver -- no input field can carry containment evidence for this leg", leg, lc.Availability)
		}
		if len(lc.Containment) != 0 {
			t.Errorf("leg %s Containment = %v, want empty", leg, lc.Containment)
		}
	}
}

func TestBuildReport_NoRansomwareRows_RansomwarePayloadLegIsNoObserver(t *testing.T) {
	report := BuildReport(Input{Context: baseContext()})
	lc := findLeg(t, report, "ransomware_payload")
	if lc.Availability != ContainmentNoObserver {
		t.Errorf("Availability = %q, want ContainmentNoObserver -- nothing was attempted", lc.Availability)
	}
	if len(lc.Containment) != 0 {
		t.Errorf("Containment = %v, want empty", lc.Containment)
	}
}

func TestBuildReport_MultiTechniqueContainmentIndependence(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	rows := []db.RWAttemptRow{
		containmentRow("T1486", "containment", "encrypt", controlval.VerdictPass, "", t0),
		containmentRow("T1490", "containment", "vss-delete", controlval.VerdictSkipped, controlval.SkipNotApplicable, t0),
		containmentRow("T1560.001", "prevention", "staging", controlval.VerdictFail, "", t0), // attempted (has a prevention row), zero containment rows
	}
	report := BuildReport(Input{Context: baseContext(), RansomwareRows: rows})

	leg := findLeg(t, report, "ransomware_payload")
	if leg.Availability != ContainmentMeasured {
		t.Fatalf("Availability = %q, want ContainmentMeasured", leg.Availability)
	}
	if len(leg.Containment) != 3 {
		t.Fatalf("got %d containment entries, want 3 (one per distinct technique)", len(leg.Containment))
	}

	t1486 := findContainment(t, report, "T1486")
	if t1486.Status != ContainmentStatusEvaluated {
		t.Errorf("T1486 Status = %q, want evaluated", t1486.Status)
	}
	if t1486.Verdict != controlval.VerdictPass {
		t.Errorf("T1486 Verdict = %q, want PASS", t1486.Verdict)
	}

	t1490 := findContainment(t, report, "T1490")
	if t1490.Status != ContainmentStatusNotApplicable {
		t.Errorf("T1490 Status = %q, want not_applicable", t1490.Status)
	}
	if t1490.Verdict == controlval.VerdictPass {
		t.Error("T1490's Verdict was contaminated by T1486's PASS verdict")
	}

	t1560 := findContainment(t, report, "T1560.001")
	if t1560.Status != ContainmentStatusNotInstrumented {
		t.Errorf("T1560.001 Status = %q, want not_instrumented -- attempted but has zero containment rows", t1560.Status)
	}
	if !t1560.CreatedAt.IsZero() {
		t.Errorf("T1560.001 CreatedAt = %v, want zero-value -- there is no containment row to read it from", t1560.CreatedAt)
	}
}

func TestBuildReport_DuplicateContainmentRowsSameTimestamp_DeterministicActionTiebreak(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	rowsA := []db.RWAttemptRow{
		containmentRow("T1486", "containment", "zzz-action", controlval.VerdictFail, "", t0),
		containmentRow("T1486", "containment", "aaa-action", controlval.VerdictPass, "", t0), // lexicographically smaller Action, same CreatedAt -- must win
	}
	reportA := BuildReport(Input{Context: baseContext(), RansomwareRows: rowsA})
	entryA := findContainment(t, reportA, "T1486")
	if entryA.Verdict != controlval.VerdictPass {
		t.Fatalf("Verdict = %q, want PASS (from aaa-action, the lexicographically smallest Action)", entryA.Verdict)
	}

	rowsB := []db.RWAttemptRow{rowsA[1], rowsA[0]} // reordered
	reportB := BuildReport(Input{Context: baseContext(), RansomwareRows: rowsB})
	entryB := findContainment(t, reportB, "T1486")
	if entryB.Verdict != entryA.Verdict {
		t.Fatalf("order-dependent result: %q vs %q", entryA.Verdict, entryB.Verdict)
	}
}

func TestBuildReport_TimeToIsolateAlwaysNotEstablishable(t *testing.T) {
	rows := []db.RWAttemptRow{
		containmentRow("T1486", "containment", "encrypt", controlval.VerdictPass, "", time.Now()),
	}
	report := BuildReport(Input{Context: baseContext(), RansomwareRows: rows})
	if report.TimeToIsolate != TimeToIsolateNotEstablishable {
		t.Errorf("TimeToIsolate = %q, want not_establishable -- never computed from any timestamp present elsewhere in the report", report.TimeToIsolate)
	}
	if report.TimeToIsolateReason == "" {
		t.Error("TimeToIsolateReason is empty, want a non-empty explanation")
	}
}

func TestBuildReport_EmptyAssessmentIDExcludesEverything(t *testing.T) {
	input := Input{
		Context: AssessmentContext{AssessmentID: "", RunID: "run-1"},
		ADReachability: []TaggedADReachability{
			{AssessmentID: "whatever", Result: admatrix.SimResult{Reachable: true}},
		},
	}
	report := BuildReport(input)
	if report.Correlation != CorrelationUncorrelated {
		t.Fatalf("Correlation = %q, want uncorrelated", report.Correlation)
	}
	if len(report.Exclusions) != 1 {
		t.Fatalf("got %d exclusions, want 1", len(report.Exclusions))
	}
	if len(report.ADReachability) != 0 {
		t.Fatalf("got %d AD reachability entries, want 0 -- an assessment with no identity gets no conclusions", len(report.ADReachability))
	}
}

func TestBuildReport_AllItemsCorrectlyTagged_IsEstablished(t *testing.T) {
	input := Input{
		Context: baseContext(),
		ADReachability: []TaggedADReachability{
			{AssessmentID: testAssessmentID, Result: admatrix.SimResult{Reachable: true}},
		},
		LateralMovementAccess: []TaggedLateralMovementAccess{
			{AssessmentID: testAssessmentID, Condition: latmove.AccessGranted},
		},
	}
	report := BuildReport(input)
	if report.Correlation != CorrelationEstablished {
		t.Fatalf("Correlation = %q, want established", report.Correlation)
	}
	if len(report.Exclusions) != 0 {
		t.Fatalf("got %d exclusions, want 0", len(report.Exclusions))
	}
}

func TestBuildReport_OneMismatchedItemAmongCorrectOnes_PartialSurvival(t *testing.T) {
	input := Input{
		Context: baseContext(),
		ADReachability: []TaggedADReachability{
			{AssessmentID: testAssessmentID, Result: admatrix.SimResult{Reachable: true}},
			{AssessmentID: "wrong-assessment", Result: admatrix.SimResult{Reachable: false}},
		},
	}
	report := BuildReport(input)
	if report.Correlation != CorrelationUncorrelated {
		t.Fatalf("Correlation = %q, want uncorrelated -- one mismatch taints the whole report", report.Correlation)
	}
	if len(report.Exclusions) != 1 {
		t.Fatalf("got %d exclusions, want exactly 1", len(report.Exclusions))
	}
	if len(report.ADReachability) != 1 {
		t.Fatalf("got %d AD reachability entries, want 1 -- the correctly-tagged item must survive", len(report.ADReachability))
	}
	if report.ADReachability[0].Reachable != true {
		t.Error("the surviving entry is not the correctly-tagged one")
	}
}

func TestBuildReport_MultipleMismatchesAcrossDifferentSources_BothRecorded(t *testing.T) {
	input := Input{
		Context: baseContext(),
		ADReachability: []TaggedADReachability{
			{AssessmentID: "wrong-1", Result: admatrix.SimResult{Reachable: true}},
		},
		LateralMovementExecution: []TaggedLateralMovementExecution{
			{AssessmentID: "wrong-2", Result: latmove.ResultExecuted},
		},
	}
	report := BuildReport(input)
	if len(report.Exclusions) != 2 {
		t.Fatalf("got %d exclusions, want 2 -- no short-circuiting after the first mismatch", len(report.Exclusions))
	}
}

func TestBuildReport_EmptyButCorrectlyTaggedLegIsEstablishedNotAMismatch(t *testing.T) {
	report := BuildReport(Input{Context: baseContext()})
	if report.Correlation != CorrelationEstablished {
		t.Fatalf("Correlation = %q, want established -- zero supplied items is not a mismatch", report.Correlation)
	}
	if len(report.Exclusions) != 0 {
		t.Fatalf("got %d exclusions, want 0", len(report.Exclusions))
	}
}

func TestBuildReport_DeterministicUnderInputReordering(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	adA := []TaggedADReachability{
		{AssessmentID: testAssessmentID, Result: admatrix.SimResult{Reachable: true}},
		{AssessmentID: "wrong", Result: admatrix.SimResult{Reachable: false}},
	}
	rowsA := []db.RWAttemptRow{
		containmentRow("T1486", "containment", "b-action", controlval.VerdictFail, "", t0),
		containmentRow("T1486", "containment", "a-action", controlval.VerdictPass, "", t0),
	}
	reportA := BuildReport(Input{Context: baseContext(), ADReachability: adA, RansomwareRows: rowsA})
	reportB := BuildReport(Input{
		Context:        baseContext(),
		ADReachability: []TaggedADReachability{adA[1], adA[0]},
		RansomwareRows: []db.RWAttemptRow{rowsA[1], rowsA[0]},
	})
	if reportA.Correlation != reportB.Correlation || len(reportA.Exclusions) != len(reportB.Exclusions) {
		t.Fatalf("order-dependent correlation result")
	}
	entryA := findContainment(t, reportA, "T1486")
	entryB := findContainment(t, reportB, "T1486")
	if entryA.Verdict != entryB.Verdict {
		t.Fatalf("order-dependent containment result: %q vs %q", entryA.Verdict, entryB.Verdict)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwpropagation/ -v`
Expected: FAIL — compile error, nothing in package `rwpropagation` is defined yet.

- [ ] **Step 3: Implement the core types**

Create `orchestrator/internal/rwpropagation/types.go`:

```go
// Package rwpropagation joins three evidence sources -- AD-mastery graph
// reachability (admatrix), lateral-movement execution/discovery evidence
// (latmove), and ransomware-payload containment evidence (rwevidence, via
// db.RWAttemptRow) -- into one report for a single simulated propagation
// incident. Pure Go, no I/O: it imports internal/db, internal/latmove,
// internal/admatrix, internal/adprimitive, and internal/controlval only
// for their types, mirroring internal/rwresponse's own precedent of
// importing internal/db for RWAttemptRow's type without ever calling the
// database. See docs/superpowers/specs/2026-10-12-cross-module-propagation-join-design.md.
package rwpropagation

import (
	"time"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/latmove"
)

// AssessmentContext identifies the single simulated incident a Report
// covers. RunID ties the ransomware leg to rwevidence's run-scoped rows;
// AssessmentID is the correlation anchor for the AD and lateral-movement
// legs, which have no run-scoped store to anchor them instead.
type AssessmentContext struct {
	AssessmentID string
	RunID        string
}

// ADReachability is one admatrix.Simulate result, carried through with
// its validation level explicit. Level is always admatrix.LevelModelSimulated
// today -- a simulated graph-reachability answer, never a claim that a
// real account can reach a live target.
type ADReachability struct {
	Target    adprimitive.Capability
	Reachable bool
	Steps     []adprimitive.Primitive
	Level     admatrix.ValidationLevel
}

// LateralMovementAccess is one latmove discovery result. Condition is
// preserved exactly (Granted/Denied/Unknown) -- never collapsed to a
// bool, and never read as if it were an ADReachability.Reachable value
// or vice versa. AD authorization and OS/network reachability are
// different questions; conflating them is exactly the
// segmentation-effectiveness mistake this package exists to avoid.
type LateralMovementAccess struct {
	Technique   latmove.Technique
	Principal   string
	Destination string
	Condition   latmove.AccessCondition
}

// LateralMovementExecution is one latmove attempt's classified outcome.
type LateralMovementExecution struct {
	Key    latmove.AttemptKey
	Result latmove.AttemptResult
}

// TechniqueContainmentStatus distinguishes WHY a technique's containment
// entry has no real verdict, when it has none -- three semantically
// different situations that must never be collapsed into one another.
type TechniqueContainmentStatus string

const (
	// ContainmentStatusEvaluated means a real PASS/FAIL/ERROR containment
	// row exists for this technique: a genuine verdict was reached.
	ContainmentStatusEvaluated TechniqueContainmentStatus = "evaluated"
	// ContainmentStatusNotApplicable means rwevidence itself decided
	// containment does not apply to this technique (a SKIPPED row with
	// SkipReason == not_applicable exists) -- a decided "no", not a gap.
	ContainmentStatusNotApplicable TechniqueContainmentStatus = "not_applicable"
	// ContainmentStatusNotInstrumented means this technique was attempted
	// in the run (it appears in the ransomware rows under some OTHER
	// capability) but carries ZERO containment-capability rows at all --
	// an instrumentation gap, never silently dropped or treated as a
	// negative (FAIL) result.
	ContainmentStatusNotInstrumented TechniqueContainmentStatus = "not_instrumented"
)

// RansomwareContainment is one ransomware technique's containment
// evidence. Scope note, load-bearing: this measures containment of the
// SPECIFIC ransomware capability attempt only -- never a claim about the
// AD or lateral-movement legs, which have no containment observer at
// all (see ContainmentNoObserver below). Verdict and CreatedAt are
// zero-valued when Status == ContainmentStatusNotInstrumented.
type RansomwareContainment struct {
	TechniqueID string
	Status      TechniqueContainmentStatus
	Verdict     controlval.Verdict
	Reason      string
	CreatedAt   time.Time
}

// ContainmentAvailability distinguishes "this leg has at least one
// technique-level entry to report" from "there is no observer for this
// leg at all" -- the latter is not a verdict, it is an honest statement
// that nothing in this codebase can answer the question yet.
type ContainmentAvailability string

const (
	ContainmentMeasured   ContainmentAvailability = "measured"
	ContainmentNoObserver ContainmentAvailability = "no_observer"
)

// LegContainment pairs a propagation leg with its containment
// availability and, only when Measured, one entry per distinct
// TechniqueID attempted on that leg. Never one value standing in for
// several techniques: T1486's containment outcome must never be read as
// speaking for T1490's, T1567.002's, or T1560.001's.
type LegContainment struct {
	Leg          string // "ad" | "lateral_movement" | "ransomware_payload"
	Availability ContainmentAvailability
	Containment  []RansomwareContainment
}

// TimeToIsolateStatus mirrors rwresponse.ResponseLatencyStatus's
// semantics exactly: a fixed status, never a computed duration, because
// no causal link between a detection event and an isolation action
// exists anywhere in this codebase today. Reused rather than reinvented.
type TimeToIsolateStatus string

const TimeToIsolateNotEstablishable TimeToIsolateStatus = "not_establishable"
```

- [ ] **Step 4: Implement the correlation and containment-derivation logic**

Create `orchestrator/internal/rwpropagation/correlate.go`:

```go
package rwpropagation

import (
	"sort"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/latmove"
)

// TaggedADReachability tags one admatrix.Simulate result with the
// AssessmentID the caller claims it belongs to.
type TaggedADReachability struct {
	AssessmentID string
	Result       admatrix.SimResult
}

// TaggedLateralMovementAccess tags one latmove discovery result.
type TaggedLateralMovementAccess struct {
	AssessmentID string
	Technique    latmove.Technique
	Principal    string
	Destination  string
	Condition    latmove.AccessCondition
}

// TaggedLateralMovementExecution tags one latmove attempt outcome.
type TaggedLateralMovementExecution struct {
	AssessmentID string
	Key          latmove.AttemptKey
	Result       latmove.AttemptResult
}

// Input is everything the caller supplies for one assessment.
// RansomwareRows' correlation to Context.RunID is enforced by
// construction, not by a field on the row: the caller is expected to
// have fetched these via db.RWCapabilityAttempts(ctx, pool,
// Context.RunID), which already filtered by run_id -- there is no
// separate RunID field on db.RWAttemptRow to check here.
type Input struct {
	Context                  AssessmentContext
	ADReachability           []TaggedADReachability
	LateralMovementAccess    []TaggedLateralMovementAccess
	LateralMovementExecution []TaggedLateralMovementExecution
	RansomwareRows           []db.RWAttemptRow
}

// Exclusion records one supplied item this package declined to include
// in the report, and why -- never dropped silently.
type Exclusion struct {
	Source string // "ad_reachability" | "lateral_movement_access" | "lateral_movement_execution"
	Reason string
}

// CorrelationStatus says whether every supplied item could be verified
// as pertaining to Context.AssessmentID.
type CorrelationStatus string

const (
	CorrelationEstablished  CorrelationStatus = "established"
	CorrelationUncorrelated CorrelationStatus = "uncorrelated"
)

// Report is the full cross-module propagation assessment for one
// AssessmentContext.
type Report struct {
	Assessment  AssessmentContext
	Correlation CorrelationStatus
	Exclusions  []Exclusion

	ADReachability            []ADReachability
	LateralMovementAccess     []LateralMovementAccess
	LateralMovementExecution  []LateralMovementExecution
	Containment               []LegContainment
	TimeToIsolate             TimeToIsolateStatus
	TimeToIsolateReason       string
}

const timeToIsolateReason = "no causal link between a detection event and an isolation action exists in this codebase today"

// BuildReport joins input's three evidence sources into one Report for
// input.Context. Never returns an error -- every "something was off"
// case is a value in the result.
func BuildReport(input Input) Report {
	report := Report{Assessment: input.Context}

	emptyContext := input.Context.AssessmentID == ""

	for _, item := range input.ADReachability {
		if emptyContext || item.AssessmentID != input.Context.AssessmentID {
			report.Exclusions = append(report.Exclusions, Exclusion{
				Source: "ad_reachability",
				Reason: exclusionReason(emptyContext, item.AssessmentID, input.Context.AssessmentID),
			})
			continue
		}
		report.ADReachability = append(report.ADReachability, ADReachability{
			Target:    item.Result.Target,
			Reachable: item.Result.Reachable,
			Steps:     item.Result.Steps,
			Level:     item.Result.Level,
		})
	}

	for _, item := range input.LateralMovementAccess {
		if emptyContext || item.AssessmentID != input.Context.AssessmentID {
			report.Exclusions = append(report.Exclusions, Exclusion{
				Source: "lateral_movement_access",
				Reason: exclusionReason(emptyContext, item.AssessmentID, input.Context.AssessmentID),
			})
			continue
		}
		report.LateralMovementAccess = append(report.LateralMovementAccess, LateralMovementAccess{
			Technique:   item.Technique,
			Principal:   item.Principal,
			Destination: item.Destination,
			Condition:   item.Condition,
		})
	}

	for _, item := range input.LateralMovementExecution {
		if emptyContext || item.AssessmentID != input.Context.AssessmentID {
			report.Exclusions = append(report.Exclusions, Exclusion{
				Source: "lateral_movement_execution",
				Reason: exclusionReason(emptyContext, item.AssessmentID, input.Context.AssessmentID),
			})
			continue
		}
		report.LateralMovementExecution = append(report.LateralMovementExecution, LateralMovementExecution{
			Key:    item.Key,
			Result: item.Result,
		})
	}

	if len(report.Exclusions) > 0 {
		report.Correlation = CorrelationUncorrelated
	} else {
		report.Correlation = CorrelationEstablished
	}

	report.Containment = []LegContainment{
		{Leg: "ad", Availability: ContainmentNoObserver},
		{Leg: "lateral_movement", Availability: ContainmentNoObserver},
		ransomwarePayloadContainment(input.RansomwareRows),
	}

	report.TimeToIsolate = TimeToIsolateNotEstablishable
	report.TimeToIsolateReason = timeToIsolateReason

	return report
}

func exclusionReason(emptyContext bool, suppliedID, contextID string) string {
	if emptyContext {
		return "no AssessmentID set on context"
	}
	return "AssessmentID mismatch: supplied " + suppliedID + ", context wants " + contextID
}

// ransomwarePayloadContainment derives the "ransomware_payload" leg from
// every distinct TechniqueID appearing anywhere in rows (any capability
// -- "attempted in this run"), sorted lexicographically for stable
// output order.
func ransomwarePayloadContainment(rows []db.RWAttemptRow) LegContainment {
	techniques := make(map[string]bool)
	for _, r := range rows {
		techniques[r.TechniqueID] = true
	}
	if len(techniques) == 0 {
		return LegContainment{Leg: "ransomware_payload", Availability: ContainmentNoObserver}
	}

	ids := make([]string, 0, len(techniques))
	for id := range techniques {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	entries := make([]RansomwareContainment, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, containmentEntryFor(id, rows))
	}
	return LegContainment{Leg: "ransomware_payload", Availability: ContainmentMeasured, Containment: entries}
}

// containmentEntryFor builds one technique's RansomwareContainment entry.
// Zero containment rows -> not_instrumented. Otherwise the earliest row
// wins (ties broken by lexicographically-smallest Action, deterministic
// regardless of input order), and its Verdict/SkipReason decide
// not_applicable vs evaluated.
func containmentEntryFor(techniqueID string, rows []db.RWAttemptRow) RansomwareContainment {
	var containmentRows []db.RWAttemptRow
	for _, r := range rows {
		if r.TechniqueID == techniqueID && r.Capability == "containment" {
			containmentRows = append(containmentRows, r)
		}
	}
	if len(containmentRows) == 0 {
		return RansomwareContainment{TechniqueID: techniqueID, Status: ContainmentStatusNotInstrumented}
	}

	sort.Slice(containmentRows, func(i, j int) bool {
		a, b := containmentRows[i], containmentRows[j]
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.Action < b.Action
	})
	r := containmentRows[0]

	status := ContainmentStatusEvaluated
	if r.Verdict == controlval.VerdictSkipped && r.SkipReason == controlval.SkipNotApplicable {
		status = ContainmentStatusNotApplicable
	}
	return RansomwareContainment{
		TechniqueID: techniqueID,
		Status:      status,
		Verdict:     r.Verdict,
		Reason:      r.Reason,
		CreatedAt:   r.CreatedAt,
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwpropagation/ -v`
Expected: PASS (15/15 — all tests from Step 1)

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/rwpropagation/types.go internal/rwpropagation/correlate.go internal/rwpropagation/correlate_test.go
git commit -m "feat(rwpropagation): cross-module join -- per-technique containment, never collapsed

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Real cross-package end-to-end test and final regression

**Files:**
- Create: `orchestrator/internal/rwpropagation/crosspackage_test.go`

**Interfaces:**
- Consumes: `admatrix.Simulate(catalog []adprimitive.Primitive, env adenv.Environment, attacker string, held []adprimitive.Capability, target adprimitive.Capability) SimResult` (`internal/admatrix/matrix.go`); `latmove.ClassifyAttempt(obs Observation) AttemptResult`, `latmove.Observation{Key AttemptKey, Marker MarkerCheck, ...}`, `latmove.MarkerCheck{Correlated, Found bool}` (`internal/latmove/observation.go`); `adenv.Environment` (`internal/adenv/types.go`) — all from Task 1's `BuildReport`, `Input`, and tagged types.
- Produces: nothing new for later tasks — this sub-project ends here.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/rwpropagation/crosspackage_test.go`:

```go
package rwpropagation

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/latmove"
)

// TestBuildReport_RealCrossPackageEndToEnd exercises BuildReport with
// genuine values from admatrix, latmove, and db -- not just this
// package's own literals -- to catch any mismatch between the spec's
// illustrative code and the real packages' actual shapes.
func TestBuildReport_RealCrossPackageEndToEnd(t *testing.T) {
	// target is already held, so adchain.Plan short-circuits to
	// Reachable=true with zero steps -- the simplest real Simulate call.
	target := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin, Target: "DC01"}
	simResult := admatrix.Simulate(
		[]adprimitive.Primitive{},
		adenv.Environment{},
		"attacker1",
		[]adprimitive.Capability{target},
		target,
	)

	obs := latmove.Observation{
		Key:    latmove.AttemptKey{RunID: "run-1", Source: "host1", Destination: "host2", Technique: "T1047"},
		Marker: latmove.MarkerCheck{Correlated: true, Found: true},
	}
	execResult := latmove.ClassifyAttempt(obs)

	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	rows := []db.RWAttemptRow{
		{TechniqueID: "T1486", Action: "encrypt", Capability: "containment", Verdict: controlval.VerdictPass, CreatedAt: t0},
		{TechniqueID: "T1490", Action: "vss-delete", Capability: "prevention", Verdict: controlval.VerdictFail, CreatedAt: t0},
	}

	input := Input{
		Context: baseContext(),
		ADReachability: []TaggedADReachability{
			{AssessmentID: testAssessmentID, Result: simResult},
		},
		LateralMovementExecution: []TaggedLateralMovementExecution{
			{AssessmentID: testAssessmentID, Key: obs.Key, Result: execResult},
		},
		RansomwareRows: rows,
	}
	report := BuildReport(input)

	if report.Correlation != CorrelationEstablished {
		t.Fatalf("Correlation = %q, want established", report.Correlation)
	}
	if len(report.ADReachability) != 1 || !report.ADReachability[0].Reachable || report.ADReachability[0].Level != admatrix.LevelModelSimulated {
		t.Fatalf("AD reachability entry wrong: %+v", report.ADReachability)
	}
	if len(report.LateralMovementExecution) != 1 || report.LateralMovementExecution[0].Result != latmove.ResultExecuted {
		t.Fatalf("lateral movement execution entry wrong: %+v", report.LateralMovementExecution)
	}

	leg := findLeg(t, report, "ransomware_payload")
	if leg.Availability != ContainmentMeasured {
		t.Fatalf("Availability = %q, want measured", leg.Availability)
	}
	t1486 := findContainment(t, report, "T1486")
	if t1486.Status != ContainmentStatusEvaluated {
		t.Errorf("T1486 Status = %q, want evaluated", t1486.Status)
	}
	t1490 := findContainment(t, report, "T1490")
	if t1490.Status != ContainmentStatusNotInstrumented {
		t.Errorf("T1490 Status = %q, want not_instrumented (has a prevention row, zero containment rows)", t1490.Status)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/rwpropagation/ -run "TestBuildReport_RealCrossPackageEndToEnd" -v`
Expected: FAIL if any real signature drifted from what Task 1 assumed (e.g. a compile error naming the actual mismatch) — if Task 1's grounding was accurate, this may instead run cleanly on the first try, which is still a valid outcome here since the test exercises existing, already-implemented `BuildReport` logic rather than new production code; if it passes immediately, inspect it once to confirm it is genuinely exercising real `admatrix`/`latmove` values (not silently short-circuiting) before treating it as proof.

- [ ] **Step 3: Resolve any mismatch found**

If Step 2 failed on a real signature mismatch (not a typo in the test itself), fix the mismatch in `types.go`/`correlate.go` from Task 1 to match the actual package shapes, re-run, and record what was wrong as a one-line comment at the point of the fix — this is the exact scenario this task exists to catch.

- [ ] **Step 4: Run the full package regression**

Run: `cd orchestrator && go test ./internal/rwpropagation/ -v`
Expected: PASS (16/16 — Task 1's 15 plus this task's 1). No background run needed, no testcontainers, no memory-pressure constraint applies — this package makes no database or HTTP calls, unlike every other sub-project this session.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/rwpropagation/crosspackage_test.go
git commit -m "test(rwpropagation): real cross-package end-to-end proof

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```
