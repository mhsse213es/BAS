package wafverify

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func mustReproductionScenario(t *testing.T) ReproductionScenario {
	t.Helper()
	s, err := NewReproductionScenario("WAFVERIFY-003", "x", "y")
	if err != nil {
		t.Fatalf("NewReproductionScenario: %v", err)
	}
	return s
}

func TestNewReproductionScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewReproductionScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestEvaluateReproduction_MatchingVerdicts_ReturnsConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, reason, err := EvaluateReproduction(scenario, wafval.VerdictBlocked, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionConfirmed)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateReproduction_DifferingVerdicts_ReturnsNotConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictBlocked, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionNotConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionNotConfirmed)
	}
}

func TestEvaluateReproduction_OriginalInconclusive_ReturnsInconclusive(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictInconclusive, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionInconclusive {
		t.Errorf("status = %q, want %q", status, ReproductionInconclusive)
	}
}

func TestEvaluateReproduction_AttemptInconclusive_ReturnsInconclusive(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictBlocked, wafval.VerdictInconclusive)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionInconclusive {
		t.Errorf("status = %q, want %q", status, ReproductionInconclusive)
	}
}

// Review Focus: this is the one shape that must work on a matching
// pair of ClaimFalsePositive-shaped verdicts, which the ranked shapes
// (Regression/Benchmark/Remediation) structurally cannot handle.
func TestEvaluateReproduction_MatchingFalsePositiveVerdicts_ReturnsConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictAllowed, wafval.VerdictAllowed)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionConfirmed)
	}
}

func TestEvaluateReproduction_MatchingIncorrectlyBlockedVerdicts_ReturnsConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictIncorrectlyBlocked, wafval.VerdictIncorrectlyBlocked)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionConfirmed)
	}
}
