package compliance

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// An endpoint PASS with a fraud-control FAIL must be reported as a failed
// control, not as a resisted one.
func TestFraudFailOverridesEndpointPassInCompliance(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	for _, c := range m.AllControls() {
		if len(c.Control.Techniques) == 0 {
			continue
		}
		tech := c.Control.Techniques[0]
		results := []models.SimulationResult{{
			ID:           "fraud-1",
			Technique:    models.AttackTechnique{ID: tech, Name: "test"},
			Result:       models.ResultPass,
			FraudControl: &models.FraudControl{Verdict: "FAIL"},
		}}
		rep, err := m.GenerateReport(results, c.FrameworkID, "agent", "run", "scenario")
		if err != nil {
			t.Fatalf("GenerateReport: %v", err)
		}
		for _, cr := range rep.Controls {
			if cr.ID != c.Control.ID || len(cr.Evidence) == 0 {
				continue
			}
			if cr.Passed != 0 || cr.Failed != 1 {
				t.Fatalf("control %s: passed=%d failed=%d, want passed=0 failed=1", cr.ID, cr.Passed, cr.Failed)
			}
			if cr.Evidence[0].Result != "fail" {
				t.Fatalf("evidence result = %q, want fail", cr.Evidence[0].Result)
			}
			return
		}
	}
	t.Fatal("no testable control produced evidence for the fraud-fail result")
}
