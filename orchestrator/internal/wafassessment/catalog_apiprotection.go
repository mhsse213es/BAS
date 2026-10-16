package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafapiflow"
	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectAPIProtectionScenario returns Audspect's real, current seed
// "API Protection and Contract Enforcement" scenario: wafcatalog's 3
// generic API-abuse vectors (API-001..003) plus wafapiflow's 5
// schema/auth-boundary/sensitive-workflow/GraphQL/resource-control
// vectors (APIFLOW-001..005) -- two separate, real catalogs bundled
// under one customer-facing objective, exactly as the user's critique
// asked for.
func AudspectAPIProtectionScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-API-PROTECTION",
		"API Protection and Contract Enforcement",
		"evaluate whether the WAF enforces an API's own declared contract and authorization boundaries -- schema validation, auth-scope enforcement, workflow single-use rules, GraphQL query depth, and bulk-export limits -- in addition to generic request-based API abuse",
		[]string{"API-001", "API-002", "API-003", "APIFLOW-001", "APIFLOW-002", "APIFLOW-003", "APIFLOW-004", "APIFLOW-005"},
		"target exposes the API endpoints these vectors assume (orders, profile, password-reset, GraphQL, bulk-export) behind the WAF",
		"a WAF-mechanism CollectionResult per contributing vector, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 03",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading api-protection scenario: %w", err)
	}
	knownIDs, err := apiProtectionKnownIDs()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading api-protection scenario: %w", err)
	}
	if err := ValidateAgainstKnownIDs(scenario, knownIDs); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading api-protection scenario: %w", err)
	}
	return scenario, nil
}

// apiProtectionSeverities returns the real severity of every
// contributing vector ID, converted from each source catalog's own
// Severity type to wafcatalog.Severity (a lossless conversion: both
// wafcatalog.Severity and wafapiflow.Severity are plain
// critical/high/medium/low string enums with identical values).
func apiProtectionSeverities() (map[string]wafcatalog.Severity, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	apiflow, err := wafapiflow.AudspectWAFAPIFlowCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafapiflow catalog: %w", err)
	}
	severityByID := make(map[string]wafcatalog.Severity, len(catalog)+len(apiflow))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}
	for _, v := range apiflow {
		severityByID[v.ID] = wafcatalog.Severity(string(v.Severity))
	}
	return severityByID, nil
}

func apiProtectionKnownIDs() (map[string]bool, error) {
	severityByID, err := apiProtectionSeverities()
	if err != nil {
		return nil, err
	}
	knownIDs := make(map[string]bool, len(severityByID))
	for id := range severityByID {
		knownIDs[id] = true
	}
	return knownIDs, nil
}

// AudspectAPIProtectionFixtures returns Audspect's real, current seed
// fixture set for the API-protection scenario -- deliberately NOT a
// uniform pass. APIFLOW-003 (SeverityCritical, password-reset token
// replay) is seeded as Missed, a deliberate simulated bypass, so the
// scenario genuinely resolves to ScenarioFail. API-003 is deliberately
// absent (untested).
func AudspectAPIProtectionFixtures() (map[string]VectorFixture, error) {
	return map[string]VectorFixture{
		"API-001":      blocked("API-001"),
		"API-002":      blocked("API-002"),
		"APIFLOW-001":  blocked("APIFLOW-001"),
		"APIFLOW-002":  blocked("APIFLOW-002"),
		"APIFLOW-003":  missed("APIFLOW-003"),
		"APIFLOW-004":  blocked("APIFLOW-004"),
		"APIFLOW-005":  blocked("APIFLOW-005"),
	}, nil
}
