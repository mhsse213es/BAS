package wafassessment

import (
	"github.com/audspect/bas/internal/waforigin"
	"github.com/audspect/bas/internal/wafval"
)

func nodeKey(id string) wafval.CorrelationKey {
	return wafval.CorrelationKey{TestExecutionID: id, RequestID: id}
}

// AudspectOriginResilienceScenario returns Audspect's real, current
// seed "Resilience, Failover and Enforcement Continuity" scenario: all
// 5 real waforigin scenarios (WAFORIGIN-001/002/003 bypass pairs,
// WAFORIGIN-004 protocol claim, WAFORIGIN-005 cross-node consistency).
func AudspectOriginResilienceScenario() (EnterpriseScenario, error) {
	return NewEnterpriseScenario(
		"WAFSCENARIO-ORIGIN-RESILIENCE",
		"Resilience, Failover and Enforcement Continuity",
		"evaluate whether the WAF's enforcement survives deployment-topology conditions beyond the single documented request path -- undocumented routes, direct origin reachability, fail-open behavior during WAF unavailability, TLS/proxy-trust forgery, and configuration drift across enforcement nodes",
		[]string{"WAFORIGIN-001", "WAFORIGIN-002", "WAFORIGIN-003", "WAFORIGIN-004", "WAFORIGIN-005"},
		"target's documented WAF path and at least one alternate/bypass path (undocumented route, direct origin, degraded-WAF state) are both reachable, with multiple enforcement nodes for the cross-node vector",
		"baseline/bypass evidence pairs, malicious-leg evidence, or per-node evidence depending on evaluation kind, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 10",
	)
}

// AudspectOriginResilienceFixtures returns Audspect's real, current
// seed fixture set for the origin-resilience scenario -- deliberately
// NOT a uniform pass. WAFORIGIN-005 (cross-node consistency, tied to
// PATHTRAV-001, SeverityCritical) is seeded with two trustworthy nodes
// disagreeing -- a deliberate simulated configuration drift, so the
// scenario genuinely resolves to ScenarioFail. WAFORIGIN-003 is
// deliberately absent (untested).
func AudspectOriginResilienceFixtures() map[string]OriginResilienceFixture {
	return map[string]OriginResilienceFixture{
		"WAFORIGIN-001": {
			BaselineEvidence: blocked("WAFORIGIN-001-baseline").Results,
			BypassEvidence:   blocked("WAFORIGIN-001-bypass").Results,
		},
		"WAFORIGIN-002": {
			BaselineEvidence: blocked("WAFORIGIN-002-baseline").Results,
			BypassEvidence:   blocked("WAFORIGIN-002-bypass").Results,
		},
		"WAFORIGIN-004": {ProtocolEvidence: blocked("WAFORIGIN-004").Results},
		"WAFORIGIN-005": {
			NodeEvidence: []waforigin.NodeEvidence{
				{NodeID: "edge-node-a", Evidence: blocked("WAFORIGIN-005-node-a").Results, Key: nodeKey("WAFORIGIN-005-node-a")},
				{NodeID: "edge-node-b", Evidence: missed("WAFORIGIN-005-node-b").Results, Key: nodeKey("WAFORIGIN-005-node-b")},
			},
		},
	}
}
