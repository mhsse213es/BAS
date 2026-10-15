package wafpolicygap

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func checkVectorMatch(scenario PolicyGapScenario, vector wafcatalog.AttackVector) error {
	if vector.ID != scenario.AttackVectorID {
		return fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	return nil
}

// EvaluatePairedScenario drives scenario's referenced vector's malicious leg
// through baseline and weakened evidence, then wafval.EvaluatePolicyGap.
func EvaluatePairedScenario(
	scenario PolicyGapScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	baselineEvidence []wafval.CollectionResult,
	baselineKey wafval.CorrelationKey,
	weakenedEvidence []wafval.CollectionResult,
	weakenedKey wafval.CorrelationKey,
	policyDifferentiationConfirmed bool,
) (wafval.Verdict, string, error) {
	if !scenario.Weakness.IsPaired() {
		return "", "", fmt.Errorf("scenario %q has weakness %q, which is not a paired weakness -- use EvaluateCoverageGapScenario", scenario.ID, scenario.Weakness)
	}
	if err := checkVectorMatch(scenario, vector); err != nil {
		return "", "", err
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	baseline := wafval.EvaluateClaim(maliciousExpectation, baselineEvidence, baselineKey)
	weakened := wafval.EvaluateClaim(maliciousExpectation, weakenedEvidence, weakenedKey)
	pair := wafval.Pair{Baseline: baseline, Weakened: weakened, PolicyDifferentiationConfirmed: policyDifferentiationConfirmed}
	verdict, reason := wafval.EvaluatePolicyGap(pair)
	return verdict, reason, nil
}

// EvaluateCoverageGapScenario drives scenario's referenced vector's
// malicious leg through a single evidence set via wafval.EvaluateClaim.
func EvaluateCoverageGapScenario(
	scenario PolicyGapScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	evidence []wafval.CollectionResult,
	key wafval.CorrelationKey,
) (wafval.Result, error) {
	if scenario.Weakness.IsPaired() {
		return wafval.Result{}, fmt.Errorf("scenario %q has weakness %q, which is a paired weakness -- use EvaluatePairedScenario", scenario.ID, scenario.Weakness)
	}
	if err := checkVectorMatch(scenario, vector); err != nil {
		return wafval.Result{}, err
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	return wafval.EvaluateClaim(maliciousExpectation, evidence, key), nil
}
