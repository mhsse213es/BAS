package wafpolicygap

import "fmt"

// AudspectWAFPolicyGapCatalog returns Audspect's real, current seed
// policy-gap scenario catalog: exactly one scenario per WeaknessType,
// validated before being returned.
func AudspectWAFPolicyGapCatalog() ([]PolicyGapScenario, error) {
	type seed struct {
		id, attackVectorID, baselineDesc, weakenedDesc, provenance string
		weakness                                                   WeaknessType
	}
	seeds := []seed{
		{
			id: "GAP-001", weakness: WeaknessDetectionOnlyMode, attackVectorID: "POLICY-001",
			baselineDesc: "OWASP CRS default anomaly-scoring mode, rule set enabled",
			weakenedDesc: "the matching rule for this payload was switched to detection-only (log, no block)",
			provenance:   "manually authored from waf.txt Phase 3's named weak-mode category",
		},
		{
			id: "GAP-002", weakness: WeaknessExclusionRule, attackVectorID: "SQLI-001",
			baselineDesc: "the SQLi rule set applies to this endpoint's query parameters with no exclusions",
			weakenedDesc: "a targeted per-rule exclusion was added for this specific SQLi signature on this endpoint",
			provenance:   "manually authored from waf.txt Phase 3's named exclusion category",
		},
		{
			id: "GAP-003", weakness: WeaknessOverlyBroadException, attackVectorID: "POLICY-002",
			baselineDesc: "every API route, including legacy ones, is inspected by the WAF",
			weakenedDesc: "an overly broad legacy-compatibility exception exempts an entire API path prefix from inspection",
			provenance:   "manually authored from waf.txt Phase 3's named overly-broad-exception category",
		},
		{
			id: "GAP-004", weakness: WeaknessPriorityConflict, attackVectorID: "XSS-001",
			baselineDesc: "the block rule for this XSS signature is declared to evaluate before any allow/exception rule",
			weakenedDesc: "a lower-priority allow-rule was misconfigured to evaluate before the higher-priority block-rule, causing a bypass",
			provenance:   "manually authored from waf.txt Phase 3's named priority-conflict category",
		},
		{
			id: "GAP-005", weakness: WeaknessUnprotectedRoute, attackVectorID: "SSRF-001",
			baselineDesc: "declared policy: every API route, including webhook endpoints, sits behind the WAF",
			weakenedDesc: "this route was never added to the WAF's protected hostname/path set",
			provenance:   "manually authored from waf.txt Phase 3's named unprotected-route category",
		},
		{
			id: "GAP-006", weakness: WeaknessMissingCoverage, attackVectorID: "API-001",
			baselineDesc: "declared policy: all API routes under /api/ are covered by the WAF's API-abuse rule set",
			weakenedDesc: "this specific route was added to the application after the WAF policy was last updated, and the policy was never revised to cover it",
			provenance:   "manually authored from waf.txt Phase 3's named missing-coverage category",
		},
	}

	var out []PolicyGapScenario
	for _, sd := range seeds {
		s, err := NewPolicyGapScenario(sd.id, sd.weakness, sd.attackVectorID, sd.baselineDesc, sd.weakenedDesc, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed policy-gap catalog: %w", err)
		}
		out = append(out, s)
	}

	if err := ValidatePolicyGapCatalog(out); err != nil {
		return nil, fmt.Errorf("seed policy-gap catalog failed validation: %w", err)
	}
	return out, nil
}
