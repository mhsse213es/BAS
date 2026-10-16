package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// AudspectExploitPreventionScenario returns Audspect's real, current
// seed "Exploit Prevention and Attack-Chain Validation" scenario: the
// 8 real injection/XSS/path-traversal vectors from wafcatalog,
// validated against the real catalog before returning.
func AudspectExploitPreventionScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-EXPLOIT-PREVENTION",
		"Exploit Prevention and Attack-Chain Validation",
		"evaluate whether the WAF prevents multiple classes of web exploitation (SQL injection, XSS, path traversal) across application routes and payload variations",
		[]string{"SQLI-001", "SQLI-002", "SQLI-003", "XSS-001", "XSS-002", "XSS-003", "PATHTRAV-001", "PATHTRAV-002"},
		"target exposes the application routes these vectors assume (search, login, products, comments, profile, download, static assets)",
		"a WAF-mechanism CollectionResult per contributing vector, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 01",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading exploit-prevention scenario: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading exploit-prevention scenario: %w", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading exploit-prevention scenario: %w", err)
	}
	return scenario, nil
}

func blocked(vectorID string) VectorFixture {
	return VectorFixture{VectorID: vectorID, Results: []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementBlocked, EvidenceKind: wafval.EvidenceObserved},
		}},
	}}
}

func missed(vectorID string) VectorFixture {
	return VectorFixture{VectorID: vectorID, Results: []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, EvidenceKind: wafval.EvidenceObserved},
		}},
	}}
}

// AudspectExploitPreventionFixtures returns Audspect's real, current
// seed fixture set for the exploit-prevention scenario -- deliberately
// NOT a uniform "everything passes" demo. SQLI-002 (SeverityCritical)
// is seeded as Missed, a deliberate simulated bypass, so the scenario
// genuinely resolves to ScenarioFail despite 5 other vectors blocking
// cleanly. XSS-002 and PATHTRAV-002 are deliberately absent, so they
// surface as untested rather than silently passing.
func AudspectExploitPreventionFixtures() (map[string]VectorFixture, error) {
	return map[string]VectorFixture{
		"SQLI-001":     blocked("SQLI-001"),
		"SQLI-002":     missed("SQLI-002"),
		"SQLI-003":     blocked("SQLI-003"),
		"XSS-001":      blocked("XSS-001"),
		"XSS-003":      blocked("XSS-003"),
		"PATHTRAV-001": blocked("PATHTRAV-001"),
	}, nil
}
