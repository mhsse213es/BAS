package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafbotabuse"
	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectAutomatedAbuseScenario returns Audspect's real, current seed
// "Automated Abuse and Resource Protection" scenario: wafcatalog's 2
// generic rate-limit vectors (RATE-001/002) plus wafbotabuse's 4
// bounded-automation/rate-limit/credential-abuse/distributed-enforcement
// vectors (BOTABUSE-001..004) -- two separate, real catalogs bundled
// under one customer-facing objective.
func AudspectAutomatedAbuseScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-AUTOMATED-ABUSE",
		"Automated Abuse and Resource Protection",
		"evaluate whether the WAF distinguishes human-paced traffic from automated abuse -- scripted bursts, distributed rate-limit evasion, credential-stuffing lockout bypass, and cross-node lockout-state consistency -- in addition to generic per-endpoint rate limiting",
		[]string{"RATE-001", "RATE-002", "BOTABUSE-001", "BOTABUSE-002", "BOTABUSE-003", "BOTABUSE-004"},
		"target exposes the endpoints these vectors assume (pricing, search, order-creation, login lockout) behind the WAF, with multiple enforcement nodes for the cross-node vector",
		"a WAF-mechanism CollectionResult per contributing vector, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 04",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading automated-abuse scenario: %w", err)
	}
	knownIDs, err := automatedAbuseKnownIDs()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading automated-abuse scenario: %w", err)
	}
	if err := ValidateAgainstKnownIDs(scenario, knownIDs); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading automated-abuse scenario: %w", err)
	}
	return scenario, nil
}

// automatedAbuseSeverities returns the real severity of every
// contributing vector ID, converted from each source catalog's own
// Severity type to wafcatalog.Severity (lossless: both are plain
// critical/high/medium/low string enums).
func automatedAbuseSeverities() (map[string]wafcatalog.Severity, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	botabuse, err := wafbotabuse.AudspectWAFBotAbuseCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafbotabuse catalog: %w", err)
	}
	severityByID := make(map[string]wafcatalog.Severity, len(catalog)+len(botabuse))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}
	for _, v := range botabuse {
		severityByID[v.ID] = wafcatalog.Severity(string(v.Severity))
	}
	return severityByID, nil
}

func automatedAbuseKnownIDs() (map[string]bool, error) {
	severityByID, err := automatedAbuseSeverities()
	if err != nil {
		return nil, err
	}
	knownIDs := make(map[string]bool, len(severityByID))
	for id := range severityByID {
		knownIDs[id] = true
	}
	return knownIDs, nil
}

// AudspectAutomatedAbuseFixtures returns Audspect's real, current seed
// fixture set for the automated-abuse scenario -- deliberately NOT a
// uniform pass. BOTABUSE-004 (SeverityCritical, cross-node
// lockout-state bypass) is seeded as Missed, a deliberate simulated
// bypass, so the scenario genuinely resolves to ScenarioFail.
// RATE-002 is deliberately absent (untested).
func AudspectAutomatedAbuseFixtures() (map[string]VectorFixture, error) {
	return map[string]VectorFixture{
		"RATE-001":     blocked("RATE-001"),
		"BOTABUSE-001": blocked("BOTABUSE-001"),
		"BOTABUSE-002": blocked("BOTABUSE-002"),
		"BOTABUSE-003": blocked("BOTABUSE-003"),
		"BOTABUSE-004": missed("BOTABUSE-004"),
	}, nil
}
