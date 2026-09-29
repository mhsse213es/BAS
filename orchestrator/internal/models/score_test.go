package models

import "testing"

func res(tactic string, r CheckResult) SimulationResult {
	return SimulationResult{
		Technique: AttackTechnique{Tactic: tactic},
		Result:    r,
		Severity:  "High",
	}
}

// ResultError (BAS could not execute) must be excluded from the prevention
// score exactly like ResultSkipped — it is not a security finding. Here one
// real fail + one error must read as 0% prevention over a single executed
// technique, with the error surfaced in its own count, not as a failure.
func TestComputeScoreExcludesErrorFromScoring(t *testing.T) {
	results := []SimulationResult{
		res("execution", ResultFail),  // genuine finding
		res("execution", ResultError), // BAS problem — excluded
		res("execution", ResultPass),  // blocked
	}
	s := ComputeScore(results, nil)

	if s.ErroredTechniques != 1 {
		t.Errorf("ErroredTechniques = %d, want 1", s.ErroredTechniques)
	}
	if s.FailedTechniques != 1 {
		t.Errorf("FailedTechniques = %d, want 1 (error must not count as fail)", s.FailedTechniques)
	}
	if s.PassedTechniques != 1 {
		t.Errorf("PassedTechniques = %d, want 1", s.PassedTechniques)
	}
	// Prevention denominator excludes the error: 1 pass of 2 executed = 50%.
	if s.PreventionScore != 50 {
		t.Errorf("PreventionScore = %.1f, want 50 (error excluded from denominator)", s.PreventionScore)
	}
}

// ResultVetoed (Audspect's own agent refused execution under B5's
// destructive-action policy) must be excluded from the prevention score
// exactly like ResultError/ResultSkipped -- it is not a security outcome.
// Before this fix, weightedTotal incremented for every result regardless
// of category, so a vetoed step diluted the denominator with zero
// numerator contribution, LOWERING PreventionScore -- backwards, since
// Audspect declining to test something says nothing about whether the
// customer's defenses would have stopped it.
func TestComputeScoreExcludesVetoedFromScoring(t *testing.T) {
	results := []SimulationResult{
		res("execution", ResultFail),   // genuine finding
		res("execution", ResultVetoed), // Audspect refused -- excluded
		res("execution", ResultPass),   // blocked
	}
	s := ComputeScore(results, nil)

	if s.VetoedTechniques != 1 {
		t.Errorf("VetoedTechniques = %d, want 1", s.VetoedTechniques)
	}
	if s.FailedTechniques != 1 {
		t.Errorf("FailedTechniques = %d, want 1 (vetoed must not count as fail)", s.FailedTechniques)
	}
	if s.PassedTechniques != 1 {
		t.Errorf("PassedTechniques = %d, want 1 (vetoed must not count as pass)", s.PassedTechniques)
	}
	// Prevention denominator excludes the veto: 1 pass of 2 executed = 50%,
	// exactly as if the vetoed result were never submitted at all.
	if s.PreventionScore != 50 {
		t.Errorf("PreventionScore = %.1f, want 50 (vetoed excluded from denominator)", s.PreventionScore)
	}
}

// An ERROR must never become a critical finding, even at Critical severity.
func TestComputeScoreErrorIsNotACriticalFinding(t *testing.T) {
	results := []SimulationResult{
		{Technique: AttackTechnique{Tactic: "credential-access"}, Result: ResultError, Severity: "Critical"},
	}
	s := ComputeScore(results, nil)
	if len(s.CriticalFailures) != 0 {
		t.Errorf("CriticalFailures = %d, want 0 (errors are not findings)", len(s.CriticalFailures))
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
