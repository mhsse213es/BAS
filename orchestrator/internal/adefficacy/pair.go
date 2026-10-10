package adefficacy

import "github.com/audspect/bas/internal/controlval"

// Pair holds the two independent principal results. The raw Validations are
// never mutated; the acceptance gate is a separate derivation.
type Pair struct {
	Positive controlval.Validation // attacker, expected allowed
	Negative controlval.Validation // labuser, expected blocked
}

// AcceptedNegativeVerdict returns the TRUSTWORTHY verdict for the negative
// control. A negative PASS is downgraded to SKIPPED when the positive control
// did not cleanly PASS -- a denial is only trustworthy once the harness is
// shown capable of an authorized success. It never upgrades and never mutates
// the raw Validations.
func (p Pair) AcceptedNegativeVerdict() (controlval.Verdict, string) {
	if p.Negative.Verdict == controlval.VerdictPass && p.Positive.Verdict != controlval.VerdictPass {
		return controlval.VerdictSkipped,
			"negative-control denial not trustworthy: positive control did not succeed (harness not shown capable of an authorized DCSync)"
	}
	return p.Negative.Verdict, p.Negative.Reason
}
