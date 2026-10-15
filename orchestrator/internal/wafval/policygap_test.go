package wafval

import "testing"

func blockedResult(conf Confidence) Result {
	return Result{Expectation: Expectation{Claim: ClaimPrevention}, Verdict: VerdictBlocked, Confidence: conf, Completeness: CompletenessComplete}
}
func missedResult() Result {
	return Result{Expectation: Expectation{Claim: ClaimPrevention}, Verdict: VerdictMissed, Confidence: ConfidenceHigh, Completeness: CompletenessComplete}
}

func TestEvaluatePolicyGap_StrongGap(t *testing.T) {
	v, reason := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceHigh),
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictMissed {
		t.Errorf("verdict = %q, want missed", v)
	}
	if reason == "" {
		t.Error("reason must name the policy attribution")
	}
}

func TestEvaluatePolicyGap_UnconfirmedDifferentiation_Inconclusive(t *testing.T) {
	// Legs differ, but the policy change was not confirmed in force.
	v, _ := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceHigh),
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: false,
	})
	if v != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", v)
	}
}

func TestEvaluatePolicyGap_UntrustworthyBaseline_Inconclusive(t *testing.T) {
	inconclusiveBaseline := Result{Verdict: VerdictInconclusive, Confidence: ConfidenceNone}
	v, _ := EvaluatePolicyGap(Pair{
		Baseline:                       inconclusiveBaseline,
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (untrustworthy baseline)", v)
	}
}

func TestEvaluatePolicyGap_EnforcementWeaknessNotDetectionGap(t *testing.T) {
	detectedButAllowed := Result{Verdict: VerdictDetectedButAllowed, Confidence: ConfidenceHigh, Completeness: CompletenessComplete}
	v, reason := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceHigh),
		Weakened:                       detectedButAllowed,
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictDetectedButAllowed {
		t.Errorf("verdict = %q, want detected_but_allowed", v)
	}
	if reason == "" {
		t.Error("reason must distinguish enforcement weakness from detection gap")
	}
}

func TestEvaluatePolicyGap_LowConfidenceBaseline_Inconclusive(t *testing.T) {
	v, _ := EvaluatePolicyGap(Pair{
		Baseline:                       blockedResult(ConfidenceLow),
		Weakened:                       missedResult(),
		PolicyDifferentiationConfirmed: true,
	})
	if v != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (baseline Blocked but Low confidence)", v)
	}
}
