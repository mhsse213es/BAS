package wafassessment

import "fmt"

// policyIntegrityPolicyBasis names the baseline policy document every
// seed policy-gap scenario's evidence is evaluated against -- the same
// provenance string wafprofile/wafpolicygap use for their own seed
// data.
const policyIntegrityPolicyBasis = "owasp-crs-default"

// AudspectPolicyIntegrityScenario returns Audspect's real, current
// seed "Policy Integrity and Misconfiguration Exposure" scenario: all
// 6 real wafpolicygap configuration-gap scenarios (GAP-001..006), one
// per WeaknessType, validated against the real policy-gap catalog
// before returning.
func AudspectPolicyIntegrityScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-POLICY-INTEGRITY",
		"Policy Integrity and Misconfiguration Exposure",
		"evaluate whether the WAF's configured policy still enforces what it declares to -- detection-only mode, per-rule exclusions, overly broad exceptions, rule-priority conflicts, unprotected routes, and routes the policy was never updated to cover",
		[]string{"GAP-001", "GAP-002", "GAP-003", "GAP-004", "GAP-005", "GAP-006"},
		"target's WAF policy configuration is inspectable (rule modes, exclusions, exceptions, rule priority, protected-route set) alongside the real wafcatalog vectors each gap references",
		"baseline/weakened evidence pairs for paired weaknesses, single-leg coverage evidence for coverage-gap weaknesses, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 05",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading policy-integrity scenario: %w", err)
	}
	return scenario, nil
}

// AudspectPolicyIntegrityFixtures returns Audspect's real, current
// seed fixture set for the policy-integrity scenario -- deliberately
// NOT a uniform pass. GAP-002 (exclusion rule, tied to SQLI-001,
// SeverityCritical) is seeded with a trustworthy Blocked baseline and
// a Missed weakened leg under a confirmed policy differentiation --
// a deliberate simulated exclusion-rule bypass, so the scenario
// genuinely resolves to ScenarioFail. GAP-001/003/004 are seeded as
// "no gap demonstrated" (still Blocked after the claimed weakening).
// GAP-006 is seeded as covered. GAP-005 is deliberately absent
// (untested).
func AudspectPolicyIntegrityFixtures() map[string]PolicyGapFixture {
	stillBlockedPaired := func(id string) PolicyGapFixture {
		return PolicyGapFixture{
			BaselineEvidence:               blocked(id + "-baseline").Results,
			WeakenedEvidence:               blocked(id + "-weakened").Results,
			PolicyDifferentiationConfirmed: true,
		}
	}
	return map[string]PolicyGapFixture{
		"GAP-001": stillBlockedPaired("GAP-001"),
		"GAP-002": {
			BaselineEvidence:               blocked("GAP-002-baseline").Results,
			WeakenedEvidence:               missed("GAP-002-weakened").Results,
			PolicyDifferentiationConfirmed: true,
		},
		"GAP-003": stillBlockedPaired("GAP-003"),
		"GAP-004": stillBlockedPaired("GAP-004"),
		"GAP-006": {CoverageEvidence: blocked("GAP-006-coverage").Results},
	}
}
