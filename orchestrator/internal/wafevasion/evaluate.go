package wafevasion

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func trustworthyBlocked(r wafval.Result) bool {
	return r.Verdict == wafval.VerdictBlocked &&
		(r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium)
}

func decideEvasionGap(canonical, evasive wafval.Result, originEquivalenceConfirmed bool) (wafval.Verdict, string) {
	if !originEquivalenceConfirmed {
		return wafval.VerdictInconclusive, "origin-equivalence of the evasive encoding not confirmed; differing responses not attributable to the evasion technique"
	}
	if !trustworthyBlocked(canonical) {
		return wafval.VerdictInconclusive, "canonical baseline did not establish a reliable block; evasive-leg behavior cannot be attributed to the evasion technique"
	}
	switch evasive.Verdict {
	case wafval.VerdictMissed:
		return wafval.VerdictMissed, "evasion bypass confirmed: canonical payload blocked, evasive-encoded equivalent neither detected nor blocked"
	case wafval.VerdictDetectedButAllowed:
		return wafval.VerdictDetectedButAllowed, "evasion-driven enforcement gap: evasive encoding still detected but not blocked"
	case wafval.VerdictBlocked:
		return wafval.VerdictBlocked, "no evasion gap demonstrated: evasive-encoded variant still blocked"
	default:
		return wafval.VerdictInconclusive, "evasive-leg outcome not attributable to the evasion technique"
	}
}

// EvaluateEvasionGap drives scenario's referenced vector's malicious leg
// through both the canonical and evasive-encoded evidence, then applies
// decideEvasionGap. Unlike wafpolicygap's two evaluation functions, there is
// no shape check here -- every EvasionScenario is inherently a two-leg
// comparison.
func EvaluateEvasionGap(
	scenario EvasionScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	canonicalEvidence []wafval.CollectionResult,
	canonicalKey wafval.CorrelationKey,
	evasiveEvidence []wafval.CollectionResult,
	evasiveKey wafval.CorrelationKey,
	originEquivalenceConfirmed bool,
) (wafval.Verdict, string, error) {
	if vector.ID != scenario.AttackVectorID {
		return "", "", fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	canonical := wafval.EvaluateClaim(maliciousExpectation, canonicalEvidence, canonicalKey)
	evasive := wafval.EvaluateClaim(maliciousExpectation, evasiveEvidence, evasiveKey)
	verdict, reason := decideEvasionGap(canonical, evasive, originEquivalenceConfirmed)
	return verdict, reason, nil
}
