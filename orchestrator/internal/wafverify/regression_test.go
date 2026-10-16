package wafverify

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestVerdictRank_RankedValuesInOrder(t *testing.T) {
	missedRank, missedOK := verdictRank(wafval.VerdictMissed)
	detectedRank, detectedOK := verdictRank(wafval.VerdictDetectedButAllowed)
	blockedRank, blockedOK := verdictRank(wafval.VerdictBlocked)
	if !missedOK || !detectedOK || !blockedOK {
		t.Fatalf("expected all 3 ranked verdicts to report ok=true, got missed=%v detected=%v blocked=%v", missedOK, detectedOK, blockedOK)
	}
	if !(missedRank < detectedRank && detectedRank < blockedRank) {
		t.Errorf("ranks = missed:%d detected:%d blocked:%d, want missed < detected < blocked", missedRank, detectedRank, blockedRank)
	}
}

func TestVerdictRank_UnrankedValues(t *testing.T) {
	for _, v := range []wafval.Verdict{wafval.VerdictAllowed, wafval.VerdictIncorrectlyBlocked, wafval.VerdictInconclusive} {
		if _, ok := verdictRank(v); ok {
			t.Errorf("verdictRank(%q) ok = true, want false", v)
		}
	}
}

func mustRegressionScenario(t *testing.T) RegressionScenario {
	t.Helper()
	s, err := NewRegressionScenario("WAFVERIFY-001", "x", "y")
	if err != nil {
		t.Fatalf("NewRegressionScenario: %v", err)
	}
	return s
}

func TestNewRegressionScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewRegressionScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewRegressionScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewRegressionScenario("WAFVERIFY-001", "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewRegressionScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewRegressionScenario("WAFVERIFY-001", "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func TestEvaluateRegression_EqualRanks_ReturnsStable(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, reason, err := EvaluateRegression(scenario, wafval.VerdictBlocked, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionStable {
		t.Errorf("status = %q, want %q", status, RegressionStable)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateRegression_RankIncrease_ReturnsImproved(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictMissed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionImproved {
		t.Errorf("status = %q, want %q", status, RegressionImproved)
	}
}

func TestEvaluateRegression_RankDecrease_ReturnsRegressed(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictBlocked, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionRegressed {
		t.Errorf("status = %q, want %q", status, RegressionRegressed)
	}
}

// Review Focus: a FalsePositive-shaped verdict on either side must
// trigger Inconclusive, not be silently ranked as 0.
func TestEvaluateRegression_BaselineUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictAllowed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionInconclusive {
		t.Errorf("status = %q, want %q", status, RegressionInconclusive)
	}
}

func TestEvaluateRegression_CurrentUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictBlocked, wafval.VerdictInconclusive)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionInconclusive {
		t.Errorf("status = %q, want %q", status, RegressionInconclusive)
	}
}
