// Package wafpolicygap drives internal/wafcatalog's attack vectors through
// internal/wafval's already-built two-leg policy-gap comparison
// (wafval.Pair/EvaluatePolicyGap), for configuration weaknesses that are a
// genuine baseline-vs-weakened comparison, plus a single-leg path for
// weaknesses that aren't. It depends on both wafval and wafcatalog;
// neither ever depends back on it. Zero new wafval verdict logic -- pure
// orchestration. Fixture-backed only; real execution is deferred.
package wafpolicygap

// WeaknessType is one of the six configuration-gap categories waf.txt names.
type WeaknessType string

const (
	WeaknessDetectionOnlyMode    WeaknessType = "detection_only_mode"
	WeaknessExclusionRule        WeaknessType = "exclusion_rule"
	WeaknessOverlyBroadException WeaknessType = "overly_broad_exception"
	WeaknessPriorityConflict     WeaknessType = "priority_conflict"
	WeaknessUnprotectedRoute     WeaknessType = "unprotected_route"
	WeaknessMissingCoverage      WeaknessType = "missing_coverage"
)

// IsPaired reports whether w is evaluated as a baseline-vs-weakened pair
// (via wafval.Pair/EvaluatePolicyGap) or as a single-leg coverage-absence
// check (via a direct wafval.EvaluateClaim call). Detection-only mode,
// exclusion rules, overly broad exceptions, and priority conflicts all
// describe a policy that used to block something and was changed -- a
// genuine two-leg comparison. Unprotected routes and missing coverage
// describe the absence of protection from the start -- there is no
// baseline leg where it was ever covered.
func (w WeaknessType) IsPaired() bool {
	switch w {
	case WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException, WeaknessPriorityConflict:
		return true
	default:
		return false
	}
}

// PolicyGapScenario declares one configuration-gap claim against a specific,
// real AttackVector from internal/wafcatalog. BaselinePolicyDescription
// describes the declared/expected policy state; WeakenedPolicyDescription
// describes the actual gap -- for a paired scenario, the weakening applied;
// for a single-leg scenario, what's actually missing.
type PolicyGapScenario struct {
	ID                        string
	Weakness                  WeaknessType
	AttackVectorID            string
	BaselinePolicyDescription string
	WeakenedPolicyDescription string
	Provenance                string
}
