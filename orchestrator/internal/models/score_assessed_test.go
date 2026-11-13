package models

import "testing"

func assessedResult(result, severity, tactic string) SimulationResult {
	return SimulationResult{
		Result:    CheckResult(result),
		Severity:  severity,
		Technique: AttackTechnique{ID: "T1", Name: "t", Tactic: tactic},
	}
}

// A run where every step was vetoed or skipped has no security result. It must not read as "Protected" with a 0%
// score: it is not assessed, and the score says so.
func TestComputeScore_NothingExecutedIsNotAssessed(t *testing.T) {
	results := []SimulationResult{
		assessedResult(string(ResultVetoed), "High", "defense-evasion"),
		assessedResult(string(ResultSkipped), "High", "execution"),
		assessedResult(string(ResultSkipped), "High", "execution"),
	}
	s := ComputeScore(results, nil)
	if !s.NotAssessed {
		t.Error("NotAssessed = false for a run where nothing executed, want true")
	}
	if s.Classification != "Not assessed" {
		t.Errorf("Classification = %q, want %q", s.Classification, "Not assessed")
	}
	if s.Confidence != 0 {
		t.Errorf("Confidence = %d, want 0 when nothing was assessed", s.Confidence)
	}
}

// Once a step has executed, the run is assessed and keeps its normal classification.
func TestComputeScore_ExecutedRunIsAssessed(t *testing.T) {
	results := []SimulationResult{
		assessedResult(string(ResultBlocked), "High", "execution"),
		assessedResult(string(ResultVetoed), "High", "defense-evasion"),
	}
	s := ComputeScore(results, nil)
	if s.NotAssessed {
		t.Error("NotAssessed = true for a run with an executed, blocked step, want false")
	}
	if s.Classification == "Not assessed" {
		t.Error("an assessed run must not be labelled Not assessed")
	}
}
