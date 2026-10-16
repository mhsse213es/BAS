package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafpolicygap"
	"github.com/audspect/bas/internal/wafval"
)

// PolicyGapFixture is one contributing policy-gap scenario's evidence.
// A paired weakness (WeaknessType.IsPaired() true -- detection-only
// mode, exclusion rule, overly broad exception, priority conflict)
// uses BaselineEvidence/WeakenedEvidence/PolicyDifferentiationConfirmed,
// driven through the real wafpolicygap.EvaluatePairedScenario. A
// coverage-gap weakness (unprotected route, missing coverage) uses
// CoverageEvidence only, driven through
// wafpolicygap.EvaluateCoverageGapScenario -- there is no baseline leg
// where it was ever covered.
type PolicyGapFixture struct {
	BaselineEvidence               []wafval.CollectionResult
	WeakenedEvidence                []wafval.CollectionResult
	PolicyDifferentiationConfirmed bool
	CoverageEvidence               []wafval.CollectionResult
}

// EvaluateContributingPolicyGapVector grades one policy-gap scenario's
// evidence via the real wafpolicygap dispatch -- this package never
// derives a policy-gap verdict itself.
func EvaluateContributingPolicyGapVector(scenario wafpolicygap.PolicyGapScenario, vector wafcatalog.AttackVector, policyBasis string, fixture PolicyGapFixture) (wafval.Verdict, string, error) {
	if scenario.Weakness.IsPaired() {
		baselineKey := wafval.CorrelationKey{TestExecutionID: scenario.ID + "-baseline", RequestID: scenario.ID + "-baseline"}
		weakenedKey := wafval.CorrelationKey{TestExecutionID: scenario.ID + "-weakened", RequestID: scenario.ID + "-weakened"}
		return wafpolicygap.EvaluatePairedScenario(scenario, vector, policyBasis, fixture.BaselineEvidence, baselineKey, fixture.WeakenedEvidence, weakenedKey, fixture.PolicyDifferentiationConfirmed)
	}
	key := wafval.CorrelationKey{TestExecutionID: scenario.ID, RequestID: scenario.ID}
	result, err := wafpolicygap.EvaluateCoverageGapScenario(scenario, vector, policyBasis, fixture.CoverageEvidence, key)
	if err != nil {
		return "", "", err
	}
	return result.Verdict, result.Reason, nil
}

// EvaluatePolicyIntegrityScenario grades scenario's contributing IDs
// -- real GAP-* identifiers from wafpolicygap.AudspectWAFPolicyGapCatalog,
// not raw wafcatalog vector IDs -- by the same non-offsetting
// precedence rule as EvaluateScenario (shared via aggregateByPrecedence):
// any failing verdict forces ScenarioFail; any inconclusive verdict or
// untested policy-gap scenario (with no failure already present)
// forces ScenarioIncomplete; otherwise ScenarioPass.
func EvaluatePolicyIntegrityScenario(scenario EnterpriseScenario, policyBasis string, fixtures map[string]PolicyGapFixture) (ScenarioResult, error) {
	gapCatalog, err := wafpolicygap.AudspectWAFPolicyGapCatalog()
	if err != nil {
		return ScenarioResult{}, fmt.Errorf("loading policy-gap catalog: %w", err)
	}
	gapByID := make(map[string]wafpolicygap.PolicyGapScenario, len(gapCatalog))
	for _, g := range gapCatalog {
		gapByID[g.ID] = g
	}
	attackCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return ScenarioResult{}, fmt.Errorf("loading attack catalog: %w", err)
	}
	vectorByID := make(map[string]wafcatalog.AttackVector, len(attackCatalog))
	for _, v := range attackCatalog {
		vectorByID[v.ID] = v
	}

	knownIDs := make(map[string]bool, len(gapByID))
	for id := range gapByID {
		knownIDs[id] = true
	}
	if err := ValidateAgainstKnownIDs(scenario, knownIDs); err != nil {
		return ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", scenario.ID, err)
	}

	return aggregateByPrecedence(scenario, func(gapID string) (VectorAssertion, bool, error) {
		fixture, ok := fixtures[gapID]
		if !ok {
			return VectorAssertion{}, false, nil
		}
		gapScenario := gapByID[gapID]
		vector, ok := vectorByID[gapScenario.AttackVectorID]
		if !ok {
			return VectorAssertion{}, false, fmt.Errorf("policy-gap scenario %q references attack-vector ID %q, which does not exist in the attack catalog", gapID, gapScenario.AttackVectorID)
		}
		verdict, reason, err := EvaluateContributingPolicyGapVector(gapScenario, vector, policyBasis, fixture)
		if err != nil {
			return VectorAssertion{}, false, fmt.Errorf("evaluating policy-gap scenario %q: %w", gapID, err)
		}
		return VectorAssertion{
			VectorID:       gapID,
			Severity:       vector.Severity,
			Verdict:        verdict,
			EvidenceSource: EvidenceSourceFixture,
			Reason:         reason,
		}, true, nil
	})
}
