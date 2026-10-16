package wafverify

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func mustRemediationScenario(t *testing.T) RemediationScenario {
	t.Helper()
	s, err := NewRemediationScenario("WAFVERIFY-004", "x", "y")
	if err != nil {
		t.Fatalf("NewRemediationScenario: %v", err)
	}
	return s
}

func TestNewRemediationScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewRemediationScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestEvaluateRemediation_RankIncrease_ReturnsFixed(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, reason, err := EvaluateRemediation(scenario, wafval.VerdictMissed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationFixed {
		t.Errorf("status = %q, want %q", status, RemediationFixed)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateRemediation_RankDecrease_ReturnsRegressed(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictBlocked, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationRegressed {
		t.Errorf("status = %q, want %q", status, RemediationRegressed)
	}
}

// Review Focus: Unchanged must be tested at the low end (still broken)...
func TestEvaluateRemediation_EqualRanksAtLowEnd_ReturnsUnchanged(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictMissed, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationUnchanged {
		t.Errorf("status = %q, want %q", status, RemediationUnchanged)
	}
}

// ...and at the high end (already fixed), to prove the label is
// neutral regardless of which rank the pair sits at.
func TestEvaluateRemediation_EqualRanksAtHighEnd_ReturnsUnchanged(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictBlocked, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationUnchanged {
		t.Errorf("status = %q, want %q", status, RemediationUnchanged)
	}
}

// Review Focus: an unrankable verdict on either side must trigger
// Inconclusive, not be silently ranked as 0.
func TestEvaluateRemediation_BaselineUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictAllowed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationInconclusive {
		t.Errorf("status = %q, want %q", status, RemediationInconclusive)
	}
}
