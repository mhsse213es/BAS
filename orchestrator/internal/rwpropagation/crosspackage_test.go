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
