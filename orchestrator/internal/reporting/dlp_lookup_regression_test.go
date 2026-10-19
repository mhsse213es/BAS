package reporting

import (
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

type probeResolver struct {
	scenarios map[string]*scenario.Scenario
}

func (p probeResolver) Get(id string) (*scenario.Scenario, bool) {
	sc, ok := p.scenarios[id]
	return sc, ok
}

func (p probeResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return []scenario.ExpectedDetection{{
		ID:              "exp-" + step.Name,
		Type:            scenario.DomainEndpoint,
		OutcomeFamily:   "dlp",
		Verification:    scenario.VerificationAutomatic,
		ExpectedOutcome: "Block",
		Confidence:      scenario.ConfidenceRequired,
		Finding:         scenario.ExpectedFinding{Title: step.Name, Severity: "High", Remediation: "fix"},
	}}, nil
}

func TestDLPLookup_EndToEnd_EvidenceReachesVerdict(t *testing.T) {
	raw, err := os.ReadFile("../../../scenarios/dlp-exfiltration-db-export.yaml")
	if err != nil {
		t.Fatalf("read scenario: %v", err)
	}
	sc, err := scenario.ParseYAML(raw)
	if err != nil {
		t.Fatalf("parse scenario: %v", err)
	}
	resolver := probeResolver{scenarios: map[string]*scenario.Scenario{sc.ID: sc}}
	specs := ResolveStepDetectionSpecs(resolver, sc.ID)
	if len(specs) == 0 {
		t.Fatal("no specs resolved")
	}

	// Step 1 blocked, the others succeeded: a marker the verifier must read.
	var results []models.SimulationResult
	for i, step := range sc.Steps {
		marker := "DLP_OBSERVATION: OperationSucceeded"
		if i == 0 {
			marker = "DLP_OBSERVATION: OperationBlocked"
		}
		r := scenario.Interpret(step, scenario.ExecResult{
			ExitCode:   0,
			Stdout:     marker,
			ExecutedAt: time.Now(),
		})
		results = append(results, r)
	}

	for i, r := range results {
		t.Logf("result[%d] step=%q ID=%s TechniqueID(spec)=%s", i, r.StepName, r.ID, sc.Steps[i].TechniqueID)
	}

	verdicts := ComputeAutomaticVerifications(specs, results)
	for _, v := range verdicts {
		channel, fixture := "", ""
		if v.DLPEvidence != nil {
			channel, fixture = v.DLPEvidence.Channel, v.DLPEvidence.FixtureID
		}
		t.Logf("expectation=%s observed=%s comparison=%s status=%s channel=%q fixture=%q",
			v.ExpectedID, v.ObservedOutcome, v.Comparison, v.Status, channel, fixture)
	}

	if len(verdicts) == 0 {
		t.Fatal("no verdicts produced")
	}
	if verdicts[0].ObservedOutcome != ObservationBlocked {
		t.Errorf("REGRESSION: step 1 emitted OperationBlocked but the expectation observed %q", verdicts[0].ObservedOutcome)
	}
}
