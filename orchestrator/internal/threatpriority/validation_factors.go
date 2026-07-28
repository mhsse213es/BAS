package threatpriority

import (
	"context"
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/verification"
)

type PreventionSuccessFactor struct{}

func (PreventionSuccessFactor) Name() string { return "Prevention Success" }
func (PreventionSuccessFactor) Weight(ctx Context) float64 {
	_, val := blendWeights(ctx.ValidatedCount)
	return val * coverageValidationPool / numValidationFactors
}
func (PreventionSuccessFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return validationPct(tctx, tctx.shared.preventionVerdict,
		func(v string) bool { return v == "pass" }, "prevented")
}

type ValidationSuccessFactor struct{}

func (ValidationSuccessFactor) Name() string { return "Validation Success" }
func (ValidationSuccessFactor) Weight(ctx Context) float64 {
	_, val := blendWeights(ctx.ValidatedCount)
	return val * coverageValidationPool / numValidationFactors
}
func (ValidationSuccessFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return validationPct(tctx, tctx.shared.validationVerdict,
		func(v string) bool { return v == verification.ResultDetected }, "validated")
}

// validationPct is the shared body for both Validation factors: % of the
// actor's TESTED techniques (present in idx at all) where isSuccess(verdict)
// holds. A technique never tested is excluded from the denominator, not
// counted as a failure. Unavailable only when zero techniques were tested.
func validationPct(tctx Context, idx map[string]string, isSuccess func(string) bool, label string) (float64, string, bool, error) {
	tested, success := 0, 0
	for _, id := range tctx.TechniqueIDs {
		v, ok := idx[strings.ToUpper(id)]
		if !ok {
			continue
		}
		tested++
		if isSuccess(v) {
			success++
		}
	}
	if tested == 0 {
		return 0, "Not yet validated", false, nil
	}
	pct := float64(success) / float64(tested) * 100
	return pct, fmt.Sprintf("%d of %d validated techniques %s", success, tested, label), true, nil
}
