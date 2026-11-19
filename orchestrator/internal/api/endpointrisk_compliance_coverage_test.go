package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/models"
)

func passOn(technique string) models.SimulationResult {
	return models.SimulationResult{ID: "p-" + technique, Technique: models.AttackTechnique{ID: technique}, Result: models.ResultPass}
}

func complianceHandler(t *testing.T) (*Handler, *compliance.Mapper) {
	t.Helper()
	m, err := compliance.NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{complianceMapper: m}, m
}

// One passing control out of a whole framework is a 100% resistance rate at tiny coverage: it must not be scored.
func TestComplianceInput_TooLittleTestedIsNotScored(t *testing.T) {
	h, _ := complianceHandler(t)
	got := h.complianceInput(context.Background(), "agent", time.Now(), []models.SimulationResult{passOn("T1110")})
	if got.Collected || len(got.PercentByFramework) != 0 {
		t.Fatalf("collected=%v percents=%v, want nothing scored from a single technique", got.Collected, got.PercentByFramework)
	}
	if len(got.InsufficientCoverage) == 0 {
		t.Error("no framework was reported as insufficiently covered")
	}
}

// A failed control is a finding whatever the coverage. (Control status is "failed", not the old "fail".)
func TestComplianceInput_FailedControlsStillProduceFindingsAtLowCoverage(t *testing.T) {
	h, _ := complianceHandler(t)
	failed := models.SimulationResult{ID: "f1", Technique: models.AttackTechnique{ID: "T1003"}, Result: models.ResultFail, Remediation: "Enable credential guard"}
	got := h.complianceInput(context.Background(), "agent", time.Now(), []models.SimulationResult{failed})
	if len(got.FailedFindings) == 0 {
		t.Fatal("a failed control produced no finding")
	}
	if got.FailedFindings[0].Remediation != "Enable credential guard" {
		t.Errorf("remediation = %q", got.FailedFindings[0].Remediation)
	}
	if got.Collected {
		t.Error("a single failed technique made the category scored")
	}
}

// A framework tested end to end is scored; only it appears, under its own name.
func TestComplianceInput_AFullyTestedFrameworkIsScored(t *testing.T) {
	h, m := complianceHandler(t)
	seen := map[string]bool{}
	var results []models.SimulationResult
	for _, c := range m.AllControls() {
		if c.FrameworkID != "CERT_IN" {
			continue
		}
		for _, tech := range c.Control.Techniques {
			if !seen[tech] {
				seen[tech] = true
				results = append(results, passOn(tech))
			}
		}
	}
	got := h.complianceInput(context.Background(), "agent", time.Now(), results)
	if !got.Collected {
		t.Fatal("a framework tested end to end was not scored")
	}
	const name = "CERT-In Directions on Information Security Practices"
	if pct, ok := got.PercentByFramework[name]; !ok || pct != 100 {
		t.Errorf("scored frameworks = %v, want %q at 100", got.PercentByFramework, name)
	}
	for fw := range got.PercentByFramework {
		for _, left := range got.InsufficientCoverage {
			if fw == left {
				t.Errorf("%s is both scored and listed as insufficient", fw)
			}
		}
	}
}
