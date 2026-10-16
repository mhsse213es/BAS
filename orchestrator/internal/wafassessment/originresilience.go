package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/waforigin"
	"github.com/audspect/bas/internal/wafval"
)

// originResiliencePolicyBasis names the baseline policy document every
// seed origin-resilience scenario's evidence is evaluated against.
const originResiliencePolicyBasis = "owasp-crs-default"

// OriginResilienceFixture is one contributing origin-resilience
// scenario's evidence. Which fields matter depends on which of
// waforigin's three evaluation kinds the scenario ID belongs to:
// BaselineEvidence/BypassEvidence for a Kind-A bypass-pair scenario,
// ProtocolEvidence (malicious leg only) for a Kind-B protocol-claim
// vector, NodeEvidence for a Kind-C cross-node-consistency scenario.
type OriginResilienceFixture struct {
	BaselineEvidence []wafval.CollectionResult
	BypassEvidence   []wafval.CollectionResult
	ProtocolEvidence []wafval.CollectionResult
	NodeEvidence     []waforigin.NodeEvidence
}

type originCatalogs struct {
	bypassByID      map[string]waforigin.BypassScenario
	protocolByID    map[string]waforigin.ProtocolBehaviorVector
	consistencyByID map[string]waforigin.ConsistencyScenario
	attackByID      map[string]wafcatalog.AttackVector
}

func indexBypass(s []waforigin.BypassScenario) map[string]waforigin.BypassScenario {
	m := make(map[string]waforigin.BypassScenario, len(s))
	for _, v := range s {
		m[v.ID] = v
	}
	return m
}

func indexProtocol(s []waforigin.ProtocolBehaviorVector) map[string]waforigin.ProtocolBehaviorVector {
	m := make(map[string]waforigin.ProtocolBehaviorVector, len(s))
	for _, v := range s {
		m[v.ID] = v
	}
	return m
}

func indexConsistency(s []waforigin.ConsistencyScenario) map[string]waforigin.ConsistencyScenario {
	m := make(map[string]waforigin.ConsistencyScenario, len(s))
	for _, v := range s {
		m[v.ID] = v
	}
	return m
}

func indexAttack(s []wafcatalog.AttackVector) map[string]wafcatalog.AttackVector {
	m := make(map[string]wafcatalog.AttackVector, len(s))
	for _, v := range s {
		m[v.ID] = v
	}
	return m
}

func loadOriginCatalogs() (originCatalogs, error) {
	bypass, protocol, consistency, err := waforigin.AudspectWAFOriginCatalog()
	if err != nil {
		return originCatalogs{}, fmt.Errorf("loading origin catalog: %w", err)
	}
	attackCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return originCatalogs{}, fmt.Errorf("loading attack catalog: %w", err)
	}
	return originCatalogs{
		bypassByID:      indexBypass(bypass),
		protocolByID:    indexProtocol(protocol),
		consistencyByID: indexConsistency(consistency),
		attackByID:      indexAttack(attackCatalog),
	}, nil
}

func (c originCatalogs) knownIDs() map[string]bool {
	known := make(map[string]bool, len(c.bypassByID)+len(c.protocolByID)+len(c.consistencyByID))
	for id := range c.bypassByID {
		known[id] = true
	}
	for id := range c.protocolByID {
		known[id] = true
	}
	for id := range c.consistencyByID {
		known[id] = true
	}
	return known
}

// originOutcomeClass classifies a Kind-C consistency verdict as
// failing or inconclusive. waforigin.ConsistencyVerdict is its own
// closed taxonomy ("drift_detected"/"inconclusive"/"confirmed"),
// sharing no string with wafval.Verdict's failing values -- reusing
// wafval's own failingVerdict check here would silently miss a real
// cross-node drift, the same class of bug the detection-telemetry
// scenario's design deliberately avoids. Kind A and Kind B both
// return a genuine wafval.Verdict and are classified directly by the
// caller via failingVerdict/VerdictInconclusive.
func originOutcomeClass(verdict string) (failing, inconclusive bool) {
	switch waforigin.ConsistencyVerdict(verdict) {
	case waforigin.ConsistencyDrift:
		return true, false
	case waforigin.ConsistencyInconclusive:
		return false, true
	}
	return false, false
}

// evaluateContributingOriginVector dispatches vectorID to whichever
// of waforigin's three real evaluation functions its catalog
// membership calls for, returning a VectorAssertion -- this package
// never derives an origin-resilience verdict itself. For Kind A and
// Kind B, Verdict is a genuine wafval.Verdict; for Kind C it carries
// the real ConsistencyVerdict string, classified separately by
// originOutcomeClass.
func evaluateContributingOriginVector(c originCatalogs, vectorID string, policyBasis string, fixture OriginResilienceFixture) (VectorAssertion, error) {
	if scenario, ok := c.bypassByID[vectorID]; ok {
		vector, ok := c.attackByID[scenario.AttackVectorID]
		if !ok {
			return VectorAssertion{}, fmt.Errorf("origin scenario %q references attack-vector ID %q, which does not exist in the attack catalog", vectorID, scenario.AttackVectorID)
		}
		baselineKey := wafval.CorrelationKey{TestExecutionID: vectorID + "-baseline", RequestID: vectorID + "-baseline"}
		bypassKey := wafval.CorrelationKey{TestExecutionID: vectorID + "-bypass", RequestID: vectorID + "-bypass"}
		verdict, reason, err := waforigin.EvaluateBypassScenario(scenario, vector, policyBasis, fixture.BaselineEvidence, baselineKey, fixture.BypassEvidence, bypassKey)
		if err != nil {
			return VectorAssertion{}, err
		}
		return VectorAssertion{VectorID: vectorID, Severity: vector.Severity, Verdict: verdict, EvidenceSource: EvidenceSourceFixture, Reason: reason}, nil
	}
	if vector, ok := c.protocolByID[vectorID]; ok {
		maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
		key := wafval.CorrelationKey{TestExecutionID: vectorID, RequestID: vectorID}
		result := wafval.EvaluateClaim(maliciousExpectation, fixture.ProtocolEvidence, key)
		return VectorAssertion{VectorID: vectorID, Severity: wafcatalog.Severity(""), Verdict: result.Verdict, EvidenceSource: EvidenceSourceFixture, Reason: result.Reason}, nil
	}
	if scenario, ok := c.consistencyByID[vectorID]; ok {
		vector, ok := c.attackByID[scenario.AttackVectorID]
		if !ok {
			return VectorAssertion{}, fmt.Errorf("origin scenario %q references attack-vector ID %q, which does not exist in the attack catalog", vectorID, scenario.AttackVectorID)
		}
		verdict, reason, err := waforigin.EvaluateConfigurationConsistency(scenario, vector, policyBasis, fixture.NodeEvidence)
		if err != nil {
			return VectorAssertion{}, err
		}
		return VectorAssertion{VectorID: vectorID, Severity: vector.Severity, Verdict: wafval.Verdict(verdict), EvidenceSource: EvidenceSourceFixture, Reason: reason}, nil
	}
	return VectorAssertion{}, fmt.Errorf("vector ID %q not found in any origin-resilience catalog", vectorID)
}

// EvaluateOriginResilienceScenario grades scenario's contributing
// WAFORIGIN-* IDs by the same non-offsetting precedence principle as
// EvaluateScenario, dispatched per-ID across waforigin's three
// evaluation kinds. Kind A/B failures classify via the shared
// failingVerdict/VerdictInconclusive (both produce a genuine
// wafval.Verdict); Kind C failures classify via originOutcomeClass,
// never wafval-specific logic that ConsistencyVerdict doesn't share.
func EvaluateOriginResilienceScenario(scenario EnterpriseScenario, policyBasis string, fixtures map[string]OriginResilienceFixture) (ScenarioResult, error) {
	catalogs, err := loadOriginCatalogs()
	if err != nil {
		return ScenarioResult{}, err
	}
	if err := ValidateAgainstKnownIDs(scenario, catalogs.knownIDs()); err != nil {
		return ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", scenario.ID, err)
	}

	var assertions []VectorAssertion
	var failingIDs []string
	var untested []string
	sawFailure := false
	sawIncomplete := false

	for _, id := range scenario.ContributingVectorIDs {
		fixture, ok := fixtures[id]
		if !ok {
			untested = append(untested, id)
			sawIncomplete = true
			continue
		}
		assertion, err := evaluateContributingOriginVector(catalogs, id, policyBasis, fixture)
		if err != nil {
			return ScenarioResult{}, fmt.Errorf("evaluating origin scenario %q: %w", id, err)
		}
		assertions = append(assertions, assertion)

		_, isConsistency := catalogs.consistencyByID[id]
		var failing, inconclusive bool
		if isConsistency {
			failing, inconclusive = originOutcomeClass(string(assertion.Verdict))
		} else {
			failing = failingVerdict(assertion.Verdict)
			inconclusive = assertion.Verdict == wafval.VerdictInconclusive
		}
		if failing {
			sawFailure = true
			failingIDs = append(failingIDs, fmt.Sprintf("%s (%s, %s)", id, assertion.Severity, assertion.Verdict))
		}
		if inconclusive {
			sawIncomplete = true
		}
	}

	outcome := ScenarioPass
	if sawIncomplete {
		outcome = ScenarioIncomplete
	}
	if sawFailure {
		outcome = ScenarioFail
	}

	summary := buildDetectionSummary(scenario, outcome, failingIDs, untested)
	return ScenarioResult{
		ScenarioID:        scenario.ID,
		Outcome:           outcome,
		Assertions:        assertions,
		UntestedVectorIDs: untested,
		Summary:           summary,
	}, nil
}
