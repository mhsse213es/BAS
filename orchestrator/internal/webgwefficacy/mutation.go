package webgwefficacy

// MutationResult records the three-phase outcome of one mutation
// test: whether a deliberately weakened policy was caught, and
// whether reverting it restored the scenario's original verdict.
type MutationResult struct {
	ScenarioLabel     string       `json:"scenarioLabel"`
	BaselineVerdict   WebGWVerdict `json:"baselineVerdict"`
	MutatedVerdict    WebGWVerdict `json:"mutatedVerdict"`
	RestoredVerdict   WebGWVerdict `json:"restoredVerdict"`
	CaughtRegression  bool         `json:"caughtRegression"`
	RecoveryConfirmed bool         `json:"recoveryConfirmed"`
}

// RunMutationTest proves a scenario's harness actually detects a
// deliberately-introduced regression and recovers once it is
// reverted -- webGW.txt's own quality-proof requirement #4 (weaken,
// confirm detection, restore, confirm recovery). It never weakens or
// restores a policy itself: runBaseline, runMutated, and runRestored
// are the caller's own three fixture configurations, each already
// wired to call a real Verify... function in this package.
//
// CaughtRegression is true only when the baseline was genuinely Pass
// and the mutated run flipped to Fail -- a baseline that was never
// passing cannot be credited with "catching a regression," since
// there was nothing passing to regress from.
//
// RecoveryConfirmed compares the restored verdict against the
// ORIGINAL baseline verdict, not a hardcoded Pass -- a scenario whose
// correct baseline is itself Fail (a negative-case scenario) can
// still be mutation-tested and correctly recovers by returning to
// that same Fail.
// Proven reports whether this mutation test fully proves Phase 5's
// own exit criterion -- both that a regression was caught AND that
// recovery was confirmed after reverting it. Checking CaughtRegression
// or RecoveryConfirmed alone is a half-proof; Proven is the single
// field a caller should check to claim "mutation testing passed."
func (r MutationResult) Proven() bool {
	return r.CaughtRegression && r.RecoveryConfirmed
}

func RunMutationTest(
	scenarioLabel string,
	runBaseline, runMutated, runRestored func() VerdictDetail,
) MutationResult {
	baseline := runBaseline()
	mutated := runMutated()
	restored := runRestored()

	return MutationResult{
		ScenarioLabel:     scenarioLabel,
		BaselineVerdict:   baseline.Verdict,
		MutatedVerdict:    mutated.Verdict,
		RestoredVerdict:   restored.Verdict,
		CaughtRegression:  baseline.Verdict == VerdictPass && mutated.Verdict == VerdictFail,
		RecoveryConfirmed: restored.Verdict == baseline.Verdict,
	}
}
