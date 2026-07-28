package threatpriority

import (
	"context"
	"fmt"
)

type SimulationCoverageFactor struct{}

func (SimulationCoverageFactor) Name() string { return "Simulation Coverage" }
func (SimulationCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (SimulationCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.simulation, "simulation")
}

type DetectionCoverageFactor struct{}

func (DetectionCoverageFactor) Name() string { return "Detection Coverage" }
func (DetectionCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (DetectionCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.detection, "detection profile")
}

type PurpleCoverageFactor struct{}

func (PurpleCoverageFactor) Name() string { return "Purple Exercise Coverage" }
func (PurpleCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (PurpleCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.purple, "purple exercise")
}

type ComplianceCoverageFactor struct{}

func (ComplianceCoverageFactor) Name() string { return "Compliance Mapping Coverage" }
func (ComplianceCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (ComplianceCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.compliance, "compliance mapping")
}

// coveragePct is the shared body for all 4 Coverage factors: % of the
// actor's known techniques present in idx. Unavailable only when the actor
// has zero known techniques (nothing to measure), not when the count is 0%.
func coveragePct(tctx Context, idx map[string]bool, label string) (float64, string, bool, error) {
	if len(tctx.TechniqueIDs) == 0 {
		return 0, "No known techniques for this actor", false, nil
	}
	covered := 0
	for _, id := range tctx.TechniqueIDs {
		if idx[id] {
			covered++
		}
	}
	pct := float64(covered) / float64(len(tctx.TechniqueIDs)) * 100
	return pct, fmt.Sprintf("%d of %d techniques have a %s", covered, len(tctx.TechniqueIDs), label), true, nil
}
