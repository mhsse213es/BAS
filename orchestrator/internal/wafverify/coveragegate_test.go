package wafverify

import "testing"

func TestNewCoverageGateScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewCoverageGateScenario("", "x", "y", 0.8)
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewCoverageGateScenario_NegativeMinimumCoverage_Rejected(t *testing.T) {
	_, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", -0.1)
	if err == nil {
		t.Fatal("want error for minimumCoverage < 0, got nil")
	}
}

func TestNewCoverageGateScenario_MinimumCoverageOverOne_Rejected(t *testing.T) {
	_, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", 1.1)
	if err == nil {
		t.Fatal("want error for minimumCoverage > 1, got nil")
	}
}

func TestNewCoverageGateScenario_ZeroMinimumCoverage_Succeeds(t *testing.T) {
	if _, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", 0.0); err != nil {
		t.Fatalf("NewCoverageGateScenario: %v", err)
	}
}

func TestNewCoverageGateScenario_OneMinimumCoverage_Succeeds(t *testing.T) {
	if _, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", 1.0); err != nil {
		t.Fatalf("NewCoverageGateScenario: %v", err)
	}
}

func mustCoverageGateScenario(t *testing.T, minimumCoverage float64) CoverageGateScenario {
	t.Helper()
	s, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", minimumCoverage)
	if err != nil {
		t.Fatalf("NewCoverageGateScenario: %v", err)
	}
	return s
}

func TestEvaluateCoverageGate_NegativeExercised_ReturnsError(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	if _, _, err := EvaluateCoverageGate(scenario, 10, -1); err == nil {
		t.Fatal("want error for exercisedScenarios < 0, got nil")
	}
}

func TestEvaluateCoverageGate_ExercisedExceedsTotal_ReturnsError(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	if _, _, err := EvaluateCoverageGate(scenario, 10, 11); err == nil {
		t.Fatal("want error for exercisedScenarios > totalScenarios, got nil")
	}
}

func TestEvaluateCoverageGate_ZeroTotal_ReturnsInconclusiveNotError(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	status, _, err := EvaluateCoverageGate(scenario, 0, 0)
	if err != nil {
		t.Fatalf("EvaluateCoverageGate: %v", err)
	}
	if status != CoverageGateInconclusive {
		t.Errorf("status = %q, want %q", status, CoverageGateInconclusive)
	}
}

// Review Focus: the exact-equality boundary must resolve to Pass.
func TestEvaluateCoverageGate_RatioExactlyAtThreshold_ReturnsPass(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	status, reason, err := EvaluateCoverageGate(scenario, 10, 8)
	if err != nil {
		t.Fatalf("EvaluateCoverageGate: %v", err)
	}
	if status != CoverageGatePass {
		t.Errorf("status = %q, want %q", status, CoverageGatePass)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateCoverageGate_RatioBelowThreshold_ReturnsFail(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	status, _, err := EvaluateCoverageGate(scenario, 10, 7)
	if err != nil {
		t.Fatalf("EvaluateCoverageGate: %v", err)
	}
	if status != CoverageGateFail {
		t.Errorf("status = %q, want %q", status, CoverageGateFail)
	}
}
