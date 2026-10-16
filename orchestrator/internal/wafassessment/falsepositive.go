package wafassessment

import (
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// EvaluateContributingVectorAsClaim grades one contributing vector's
// evidence against the given claim type, via the real
// wafval.EvaluateClaim -- this package never derives a verdict itself.
// EvaluateContributingVector is a thin wrapper over this for the
// ClaimPrevention case, kept for existing callers.
func EvaluateContributingVectorAsClaim(vectorID string, claim wafval.ClaimType, results []wafval.CollectionResult) (wafval.Result, error) {
	exp := wafval.Expectation{Claim: claim, PolicyVerified: false}
	key := wafval.CorrelationKey{TestExecutionID: vectorID, RequestID: vectorID}
	return wafval.EvaluateClaim(exp, results, key), nil
}

func allowedLegitFixture(vectorID string) VectorFixture {
	return VectorFixture{VectorID: vectorID, Results: []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementAllowed, EvidenceKind: wafval.EvidenceObserved},
		}},
	}}
}

func incorrectlyBlockedLegitFixture(vectorID string) VectorFixture {
	return VectorFixture{VectorID: vectorID, Results: []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementBlocked, EvidenceKind: wafval.EvidenceObserved},
		}},
	}}
}

// EvaluateLegitimateTrafficScenario grades scenario's contributing
// vectors as ClaimFalsePositive claims against their benign-traffic
// evidence -- a legitimate request incorrectly blocked
// (VerdictIncorrectlyBlocked) is this scenario's real failure mode,
// not a missed attack. Shares the same non-offsetting precedence rule
// via aggregateByPrecedence.
func EvaluateLegitimateTrafficScenario(scenario EnterpriseScenario, fixtures map[string]VectorFixture, severityByID map[string]wafcatalog.Severity) (ScenarioResult, error) {
	knownIDs := make(map[string]bool, len(severityByID))
	for id := range severityByID {
		knownIDs[id] = true
	}
	if err := ValidateAgainstKnownIDs(scenario, knownIDs); err != nil {
		return ScenarioResult{}, err
	}
	return aggregateByPrecedence(scenario, func(vectorID string) (VectorAssertion, bool, error) {
		fixture, ok := fixtures[vectorID]
		if !ok {
			return VectorAssertion{}, false, nil
		}
		result, err := EvaluateContributingVectorAsClaim(vectorID, wafval.ClaimFalsePositive, fixture.Results)
		if err != nil {
			return VectorAssertion{}, false, err
		}
		return VectorAssertion{
			VectorID:       vectorID,
			Severity:       severityByID[vectorID],
			Verdict:        result.Verdict,
			EvidenceSource: EvidenceSourceFixture,
			Reason:         result.Reason,
		}, true, nil
	})
}
