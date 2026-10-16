package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectLegitimateTrafficScenario returns Audspect's real, current
// seed "Legitimate Traffic and Business-Flow Integrity" scenario: 6
// real wafcatalog vectors confirmed to carry a non-nil
// BenignCounterpart -- the legitimate look-alike request each vector's
// malicious payload is designed to be confused with. Evaluated as a
// ClaimFalsePositive, not ClaimPrevention: this scenario's real
// failure mode is a legitimate request incorrectly blocked, not a
// missed attack.
func AudspectLegitimateTrafficScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-LEGITIMATE-TRAFFIC",
		"Legitimate Traffic and Business-Flow Integrity",
		"evaluate whether the WAF correctly allows legitimate requests that closely resemble a known attack pattern, across search, profile, file-download, upload, and pricing traffic -- a false-positive block disrupts a real business flow just as surely as a missed attack disrupts security",
		[]string{"SQLI-001", "XSS-001", "PATHTRAV-001", "API-001", "FILEUP-001", "RATE-001"},
		"target exposes the legitimate (benign) counterpart of each vector's malicious request through the WAF, on the same routes",
		"a WAF-mechanism CollectionResult per contributing vector's benign-traffic evidence, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 09",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading legitimate-traffic scenario: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading legitimate-traffic scenario: %w", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading legitimate-traffic scenario: %w", err)
	}
	return scenario, nil
}

func legitTrafficSeverities() (map[string]wafcatalog.Severity, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	severityByID := make(map[string]wafcatalog.Severity, len(catalog))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}
	return severityByID, nil
}

// AudspectLegitimateTrafficFixtures returns Audspect's real, current
// seed fixture set for the legitimate-traffic scenario -- deliberately
// NOT a uniform pass. API-001's legitimate counterpart (a normal
// order lookup) is seeded as incorrectly blocked, a deliberate
// simulated false positive, so the scenario genuinely resolves to
// ScenarioFail. FILEUP-001 is deliberately absent (untested).
func AudspectLegitimateTrafficFixtures() map[string]VectorFixture {
	return map[string]VectorFixture{
		"SQLI-001":     allowedLegitFixture("SQLI-001"),
		"XSS-001":      allowedLegitFixture("XSS-001"),
		"PATHTRAV-001": allowedLegitFixture("PATHTRAV-001"),
		"API-001":      incorrectlyBlockedLegitFixture("API-001"),
		"RATE-001":     allowedLegitFixture("RATE-001"),
	}
}
