package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectRoutingCacheIntegrityScenario returns Audspect's real,
// current seed "Application Routing and Cache Integrity" scenario:
// the 3 real wafcatalog cache-weakness vectors, validated against the
// real catalog before returning. CACHE-003 is deliberately left out of
// AudspectRoutingCacheIntegrityFixtures so this scenario's own
// UntestedVectorIDs/Incomplete path is exercised directly, not just the
// suite overall through unrelated scenarios' seed data.
func AudspectRoutingCacheIntegrityScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-ROUTING-CACHE-INTEGRITY",
		"Application Routing and Cache Integrity",
		"evaluate whether the WAF prevents cache-poisoning and cache-deception attacks that exploit unkeyed request inputs, static-looking paths on dynamic authenticated endpoints, or parameter cloaking in the cache key",
		[]string{"CACHE-001", "CACHE-002", "CACHE-003"},
		"target sits behind a caching layer (CDN or reverse-proxy cache) whose cache-key composition and static-asset routing rules are known",
		"a WAF-mechanism CollectionResult per contributing vector, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 06",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading routing-cache-integrity scenario: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading routing-cache-integrity scenario: %w", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading routing-cache-integrity scenario: %w", err)
	}
	return scenario, nil
}

// AudspectRoutingCacheIntegrityFixtures returns Audspect's real,
// current seed fixture set for the routing-cache-integrity scenario
// -- deliberately NOT a uniform pass. CACHE-001 (SeverityHigh, cache
// poisoning via unkeyed header) is seeded as Missed, a deliberate
// simulated bypass, so the scenario genuinely resolves to
// ScenarioFail. CACHE-002 is seeded as Blocked. CACHE-003 is
// deliberately absent (untested).
func AudspectRoutingCacheIntegrityFixtures() (map[string]VectorFixture, error) {
	return map[string]VectorFixture{
		"CACHE-001": missed("CACHE-001"),
		"CACHE-002": blocked("CACHE-002"),
	}, nil
}
