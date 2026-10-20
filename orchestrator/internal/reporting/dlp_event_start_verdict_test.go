package reporting

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// TestComputeAutomaticVerifications_CarriesTestEventStart checks the marker
// reaches the DLP verdict through the real pipeline: step ID, then Interpret,
// then the verifier. Two steps share the same expectation ID, so each must get
// its own start time.
func TestComputeAutomaticVerifications_CarriesTestEventStart(t *testing.T) {
	sc := &scenario.Scenario{ID: "sc-event-start", Steps: []scenario.Step{
		{Name: "step-a", TechniqueID: "T1052.001"},
		{Name: "step-b", TechniqueID: "T1052.001"},
	}}
	resolver := probeResolver{scenarios: map[string]*scenario.Scenario{sc.ID: sc}}
	specs := ResolveStepDetectionSpecs(resolver, sc.ID)

	ids := scenario.ResolvedTaskIDs(sc.Steps)
	at := "2026-10-20T04:39:43.5Z"
	var results []models.SimulationResult
	// Only step-a gets a start marker; step-b gets none.
	results = append(results, scenario.Interpret(sc.Steps[0], scenario.ExecResult{
		Stdout:     "DLP_EVENT_START: " + ids[0] + " " + at + "\nDLP_OBSERVATION: OperationSucceeded",
		ExecutedAt: time.Now(),
	}))
	results = append(results, scenario.Interpret(sc.Steps[1], scenario.ExecResult{
		Stdout:     "DLP_OBSERVATION: OperationSucceeded",
		ExecutedAt: time.Now(),
	}))

	verdicts := ComputeAutomaticVerifications(specs, results)
	byTask := map[string]VerificationResult{}
	for _, v := range verdicts {
		byTask[v.TaskID] = v
	}

	a := byTask[ids[0]]
	if a.DLPEvidence == nil {
		t.Fatal("step-a has no DLP evidence")
	}
	want, _ := time.Parse(time.RFC3339Nano, at)
	if !a.DLPEvidence.TestEventStart.Equal(want) || a.DLPEvidence.TestEventStartReason != "" {
		t.Fatalf("step-a start = %v (reason %q), want %v", a.DLPEvidence.TestEventStart, a.DLPEvidence.TestEventStartReason, want)
	}

	b := byTask[ids[1]]
	if b.DLPEvidence == nil {
		t.Fatal("step-b has no DLP evidence")
	}
	if !b.DLPEvidence.TestEventStart.IsZero() || b.DLPEvidence.TestEventStartReason != DLPEventStartNoMarker {
		t.Fatalf("step-b must have no start and reason no_marker; got %v / %q", b.DLPEvidence.TestEventStart, b.DLPEvidence.TestEventStartReason)
	}
}
