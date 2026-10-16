package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectHTTPProtocolIntegrityScenario returns Audspect's real, current
// seed "HTTP Protocol Integrity and Parser Consistency" scenario: the 2
// real wafcatalog HTTP-parser vectors, validated against the real
// catalog before returning.
func AudspectHTTPProtocolIntegrityScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-HTTP-PROTOCOL-INTEGRITY",
		"HTTP Protocol Integrity and Parser Consistency",
		"evaluate whether the WAF's HTTP parser resolves ambiguous or conflicting request framing the same way the origin does, preventing request smuggling and verb-based access-control bypass",
		[]string{"HTTPPARSE-001", "HTTPPARSE-002"},
		"target exposes an HTTP endpoint reachable through the WAF whose origin parser behavior is known (for Content-Length/Transfer-Encoding conflict resolution and verb-based routing)",
		"a WAF-mechanism CollectionResult per contributing vector, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 02",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading http-protocol-integrity scenario: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading http-protocol-integrity scenario: %w", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading http-protocol-integrity scenario: %w", err)
	}
	return scenario, nil
}

// AudspectHTTPProtocolIntegrityFixtures returns Audspect's real,
// current seed fixture set for the HTTP-protocol-integrity scenario --
// deliberately NOT a uniform pass. HTTPPARSE-001 (SeverityCritical,
// request smuggling) is seeded as Missed, a deliberate simulated
// bypass, so the scenario genuinely resolves to ScenarioFail.
// HTTPPARSE-002 is seeded as Blocked.
func AudspectHTTPProtocolIntegrityFixtures() (map[string]VectorFixture, error) {
	return map[string]VectorFixture{
		"HTTPPARSE-001": missed("HTTPPARSE-001"),
		"HTTPPARSE-002": blocked("HTTPPARSE-002"),
	}, nil
}
