package waforigin

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func trustworthyBlocked(r wafval.Result) bool {
	return r.Verdict == wafval.VerdictBlocked &&
		(r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium)
}

// decideOriginGap is local to this package, not wafval.EvaluatePolicyGap:
// the attribution story here is a network-topology/availability condition
// (an undocumented route, a path that skips the WAF, the WAF being down),
// never a policy-rule change, so EvaluatePolicyGap's PolicyDifferentiation
// semantics do not apply.
//
// The malicious leg's claim is always ClaimPrevention, so VerdictAllowed
// (reserved for ClaimFalsePositive, per wafval.derivePrevention/
// deriveFalsePositive) is never a reachable value on the bypass leg here.
// VerdictMissed is the full-gap case: the attack reached the origin
// neither detected nor blocked via the bypass path.
func decideOriginGap(baseline, bypass wafval.Result) (wafval.Verdict, string) {
	if !trustworthyBlocked(baseline) {
		return wafval.VerdictInconclusive, "baseline did not establish a reliable block through the documented path; bypass-leg behavior cannot be attributed to the bypass condition"
	}
	switch bypass.Verdict {
	case wafval.VerdictBlocked:
		return wafval.VerdictBlocked, "the bypass path did not succeed in evading enforcement -- the same attack was still blocked"
	case wafval.VerdictMissed:
		return wafval.VerdictMissed, "bypass confirmed: the same attack reached the origin neither detected nor blocked via this path"
	case wafval.VerdictDetectedButAllowed:
		return wafval.VerdictDetectedButAllowed, "the bypass path logged the attack but still allowed it through -- partial coverage gap"
	default:
		return wafval.VerdictInconclusive, "insufficient evidence to determine whether the bypass path is covered"
	}
}

// EvaluateBypassScenario drives scenario's referenced vector's malicious leg
// through both the baseline (documented-path) and bypass evidence, then
// applies decideOriginGap.
func EvaluateBypassScenario(
	scenario BypassScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	baselineEvidence []wafval.CollectionResult,
	baselineKey wafval.CorrelationKey,
	bypassEvidence []wafval.CollectionResult,
	bypassKey wafval.CorrelationKey,
) (wafval.Verdict, string, error) {
	if vector.ID != scenario.AttackVectorID {
		return "", "", fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	baseline := wafval.EvaluateClaim(maliciousExpectation, baselineEvidence, baselineKey)
	bypass := wafval.EvaluateClaim(maliciousExpectation, bypassEvidence, bypassKey)
	verdict, reason := decideOriginGap(baseline, bypass)
	return verdict, reason, nil
}
