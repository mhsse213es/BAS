package reporting

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

type endpointProbeResolver struct {
	scenarios map[string]*scenario.Scenario
}

func (p endpointProbeResolver) Get(id string) (*scenario.Scenario, bool) {
	sc, ok := p.scenarios[id]
	return sc, ok
}

func (p endpointProbeResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return []scenario.ExpectedDetection{{
		ID:           "exp-endpoint-" + step.Name,
		Type:         scenario.DomainEndpoint,
		Provider:     "microsoft_defender",
		Verification: scenario.VerificationAutomatic,
		Confidence:   scenario.ConfidenceRequired,
		Finding:      scenario.ExpectedFinding{Title: step.Name, Severity: "High", Remediation: "fix"},
	}}, nil
}

func TestEndpointLookup_EndToEnd_EvidenceReachesVerdict(t *testing.T) {
	sc := &scenario.Scenario{ID: "probe-endpoint", Steps: []scenario.Step{
		{Name: "Credential dumping via LSASS", TechniqueID: "T1003"},
	}}
	resolver := endpointProbeResolver{scenarios: map[string]*scenario.Scenario{sc.ID: sc}}
	specs := ResolveStepDetectionSpecs(resolver, sc.ID)
	if len(specs) == 0 {
		t.Fatal("no specs resolved")
	}
	r := scenario.Interpret(sc.Steps[0], scenario.ExecResult{ExitCode: 0, ExecutedAt: time.Now()})
	r.DetectionVerdict = "detected"
	r.DetectionAlert = &models.DetectionAlert{Provider: "microsoft_defender"}

	t.Logf("result step=%q ID=%s spec.TechniqueID=%s", r.StepName, r.ID, sc.Steps[0].TechniqueID)
	verdicts := ComputeAutomaticVerifications(specs, []models.SimulationResult{r})
	for _, v := range verdicts {
		t.Logf("expectation=%s observed=%s comparison=%s status=%s", v.ExpectedID, v.ObservedOutcome, v.Comparison, v.Status)
	}
	if len(verdicts) == 0 {
		t.Fatal("no verdicts produced")
	}
	if verdicts[0].Status != StatusDetected {
		t.Errorf("REGRESSION (endpoint): detected step resolved to status %q", verdicts[0].Status)
	}
}
