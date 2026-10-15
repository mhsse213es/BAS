package wafval

// Pair holds the two Prevention-shaped legs of a policy-gap comparison plus
// explicit confirmation that the weakened policy was actually in force. The raw
// Results are never mutated.
type Pair struct {
	Baseline                       Result
	Weakened                       Result
	PolicyDifferentiationConfirmed bool
}

func trustworthyBlocked(r Result) bool {
	return r.Verdict == VerdictBlocked && confRank(r.Confidence) >= confRank(ConfidenceMedium)
}

// EvaluatePolicyGap derives the pair verdict. It depends on both legs' observed
// behavior, the baseline's evidence quality, and confirmation that the policy
// difference was applied. Every verdict carries a Reason naming the attribution.
func EvaluatePolicyGap(p Pair) (Verdict, string) {
	if !p.PolicyDifferentiationConfirmed {
		return VerdictInconclusive, "policy change not confirmed in force; differing responses not attributable to the weakening"
	}
	if !trustworthyBlocked(p.Baseline) {
		return VerdictInconclusive, "baseline did not establish a reliable block; weakened-leg behavior cannot be attributed to the policy change"
	}
	switch p.Weakened.Verdict {
	case VerdictMissed:
		return VerdictMissed, "enforcement and detection gap, attributable to policy weakening (confirmed via baseline comparison)"
	case VerdictDetectedButAllowed:
		return VerdictDetectedButAllowed, "enforcement weakness; detection still fired, attributable to policy weakening (confirmed via baseline comparison)"
	case VerdictBlocked:
		return VerdictBlocked, "no gap demonstrated under this weakening; weakened policy still blocked"
	default:
		return VerdictInconclusive, "weakened-leg outcome not attributable to the policy change"
	}
}
