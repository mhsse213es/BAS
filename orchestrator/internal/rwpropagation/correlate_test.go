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
