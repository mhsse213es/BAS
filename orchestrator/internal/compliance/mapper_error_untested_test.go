package compliance

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// A control whose only evidence is an ERROR result must NOT be reported as
// "pass": an ERROR means BAS could not execute the technique, so the control
// was never actually verified. It must land in "untested" (Tested==0), exactly
// like a VETOED- or SKIPPED-only control — not fall through the
// Tested>0/Failed==0 branch and inflate the compliance score.
func TestGenerateReport_ErrorOnlyControlIsUntestedNotPass(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}

	// Pick any framework with a testable control that has at least one technique.
	var fwID, tech string
	var targetControl string
findTarget:
	for _, fw := range m.Frameworks() {
		full := m.frameworks[fw.ID]
		for _, c := range full.Controls {
			if c.IsTestable() && len(c.Techniques) > 0 {
				fwID, tech, targetControl = fw.ID, c.Techniques[0], c.ID
				break findTarget
			}
		}
	}
	if fwID == "" {
		t.Fatal("no testable control with a technique found in any framework")
	}

	results := []models.SimulationResult{{
		ID:        "r-err-1",
		Technique: models.AttackTechnique{ID: tech, Name: "test"},
		Result:    models.ResultError,
		Details:   "Execution error (exit 1): something broke in BAS",
	}}

	rep, err := m.GenerateReport(results, fwID, "agent-1", "run-1", "scenario")
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}

	var found bool
	for _, cr := range rep.Controls {
		if cr.ID != targetControl {
			continue
		}
		found = true
		if cr.Status == "pass" {
			t.Errorf("control %s with only an ERROR result reported Status=pass (tested=%d passed=%d failed=%d) — ERROR is not evidence of a passing control",
				cr.ID, cr.Tested, cr.Passed, cr.Failed)
		}
		if cr.Tested != 0 {
			t.Errorf("control %s: Tested=%d, want 0 (an ERROR result must not count as tested)", cr.ID, cr.Tested)
		}
		if cr.Status != "untested" {
			t.Errorf("control %s: Status=%q, want \"untested\"", cr.ID, cr.Status)
		}
	}
	if !found {
		t.Fatalf("target control %s not present in report", targetControl)
	}

	// And it must not inflate the summary's passing/compliance counts.
	if rep.Summary.PassingControls > 0 {
		t.Errorf("summary PassingControls=%d, want 0 (only an ERROR result was supplied)", rep.Summary.PassingControls)
	}
}
