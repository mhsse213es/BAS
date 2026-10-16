package emailgwefficacy

// MutationResult records the three-phase outcome of one mutation
// test: whether a deliberately weakened mail-security control was
// caught, and whether reverting it restored the scenario's original
// verdict -- emailGW.txt's own quality-proof requirement (weaken a
// policy in a lab, verify the relevant scenario catches the
// regression, restore, verify recovery), mirroring webgwefficacy's
// own mutation.go pattern without importing its types.
type MutationResult struct {
	ScenarioLabel     string         `json:"scenarioLabel"`
	BaselineVerdict   EmailGWVerdict `json:"baselineVerdict"`
	MutatedVerdict    EmailGWVerdict `json:"mutatedVerdict"`
	RestoredVerdict   EmailGWVerdict `json:"restoredVerdict"`
	CaughtRegression  bool           `json:"caughtRegression"`
	RecoveryConfirmed bool           `json:"recoveryConfirmed"`
}

// Proven reports whether this mutation test fully proves Phase 6's
// own exit criterion -- both that a regression was caught AND that
// recovery was confirmed after reverting it. Checking CaughtRegression
// or RecoveryConfirmed alone is a half-proof; Proven is the single
// field a caller should check to claim "mutation testing passed."
func (r MutationResult) Proven() bool {
	return r.CaughtRegression && r.RecoveryConfirmed
}

// RunMutationTest proves a scenario's harness actually detects a
// deliberately-introduced regression and recovers once it is
// reverted. It never weakens or restores a control itself:
// runBaseline, runMutated, and runRestored are the caller's own three
// fixture configurations, each already wired to call a real Verify...
// function in this package.
//
// CaughtRegression is true only when the baseline was genuinely
// ConfirmedSuccess and the mutated run flipped to ConfirmedFailure --
// a baseline that was never succeeding cannot be credited with
// "catching a regression," since there was nothing succeeding to
// regress from.
//
// RecoveryConfirmed compares the restored verdict against the
// ORIGINAL baseline verdict, not a hardcoded ConfirmedSuccess -- a
// scenario whose correct baseline is itself ConfirmedFailure (a
// negative-case scenario) can still be mutation-tested and correctly
// recovers by returning to that same ConfirmedFailure.
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
		CaughtRegression:  baseline.Verdict == VerdictConfirmedSuccess && mutated.Verdict == VerdictConfirmedFailure,
		RecoveryConfirmed: restored.Verdict == baseline.Verdict,
	}
}
