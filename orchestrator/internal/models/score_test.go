package models

import "testing"

func res(tactic string, r CheckResult) SimulationResult {
	return SimulationResult{
		Technique: AttackTechnique{Tactic: tactic},
		Result:    r,
		Severity:  "High",
	}
}

// KillChainCoverage is breadth: distinct tactics tested ÷ 14, independent of
// pass/fail. A run where every technique fails should still report non-zero
// coverage — this is the bug the metric split fixes.
func TestKillChainCoverageIsBreadthNotDefense(t *testing.T) {
	// Two distinct tactics, both with at least one failure (typical ART run).
	results := []SimulationResult{
		res("execution", ResultFail),
		res("persistence", ResultFail),
	}
	s := ComputeScore(results, nil)

	if s.CoverageScore != 0 {
		t.Errorf("CoverageScore (defense rate) = %.1f, want 0 (every tactic has a fail)", s.CoverageScore)
	}
	wantBreadth := 2.0 / float64(enterpriseTacticCount) * 100
	if s.KillChainCoverage != wantBreadth {
		t.Errorf("KillChainCoverage = %.2f, want %.2f (2 of 14 tactics)", s.KillChainCoverage, wantBreadth)
	}
	if s.KillChainCoverage == 0 {
		t.Error("KillChainCoverage must be non-zero when tactics were tested, even if all failed")
	}
}

// When every tested tactic passes, defense rate is 100% while breadth still
// reflects only how many tactics were exercised.
func TestCoverageScoreFullyBlocked(t *testing.T) {
	results := []SimulationResult{
		res("execution", ResultPass),
		res("credential-access", ResultBlocked),
	}
	s := ComputeScore(results, nil)

	if s.CoverageScore != 100 {
		t.Errorf("CoverageScore = %.1f, want 100 (all tactics fully blocked)", s.CoverageScore)
	}
	wantBreadth := 2.0 / float64(enterpriseTacticCount) * 100
	if s.KillChainCoverage != wantBreadth {
		t.Errorf("KillChainCoverage = %.2f, want %.2f", s.KillChainCoverage, wantBreadth)
	}
}
