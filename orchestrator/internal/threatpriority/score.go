package threatpriority

import "math"

const (
	// flatWeight is each curated standalone factor's (IntelFreshness,
	// Relevance, Confidence) fixed share of the composite.
	flatWeight = 0.05
	// activityWeight is ActivityFactor's fixed share -- half of
	// flatWeight, deliberately: OTX activity is a weaker, noisier signal
	// than curated intelligence, and giving it equal weight would recreate
	// exactly the "OTX pretends to be curated intel" mismatch this
	// sub-project exists to fix, just at the weighting layer instead of
	// the data layer. Composite() renormalizes proportionally across
	// whatever's Available for a given actor, so this can be tuned later
	// without a migration.
	activityWeight = 0.025
	// coverageValidationPool is what's left after the 3 curated standalone
	// factors (3 * 0.05 = 0.15): 1.0 - 0.15 = 0.85, split between Coverage
	// and Validation per blendWeights. ActivityFactor's extra 0.025 is not
	// subtracted here -- Composite() only cares about relative proportions
	// among whatever factors are Available for a given actor, so the
	// nominal weights not summing to exactly 1.0 causes no error.
	coverageValidationPool = 0.85
	numCoverageFactors     = 4.0
	numValidationFactors   = 2.0
)

// blendWeights returns (coverageWeight, validationWeight) fractions of
// coverageValidationPool for an actor with validatedCount techniques
// carrying a real verdict (prevention or validation evidence). Mirrors the
// tested-count bands ReadinessScore.ConfidenceBand already uses in
// internal/reporting/insights.go (<5 Low, 5-9 Medium, >=10 High), so the UI's
// language about confidence stays consistent across tabs.
func blendWeights(validatedCount int) (coverage, validation float64) {
	switch {
	case validatedCount >= 10:
		return 0.20, 0.80
	case validatedCount >= 5:
		return 0.60, 0.40
	default:
		return 0.90, 0.10
	}
}

func clamp100(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// Composite renormalizes across only the Available factors: a factor with
// no evidence is excluded entirely (its weight redistributed proportionally
// across the rest), never scored as 0. Returns 0 if no factor is available.
func Composite(results []FactorResult) int {
	var totalWeight, weightedSum float64
	for _, r := range results {
		if !r.Available {
			continue
		}
		totalWeight += r.Weight
		weightedSum += r.Weighted
	}
	if totalWeight <= 0 {
		return 0
	}
	return clamp100(int(math.Round(weightedSum / totalWeight)))
}
