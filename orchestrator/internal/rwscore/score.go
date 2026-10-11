package rwscore

import (
	"fmt"
	"sort"
)

var allDimensions = []Dimension{
	DimensionPrevention, DimensionDetection, DimensionContainment,
	DimensionRecovery, DimensionDataProtection,
}

// bucketDimension sums every CoverageRow belonging to dim into its 6
// buckets and computes PassRate = Pass/(Pass+Fail+Error+Unknown) -- 0 if
// that denominator is 0 (nothing to average, not NaN). NotApplicable and
// NotTested never enter this denominator (spec section B).
func bucketDimension(dim Dimension, rows []CoverageRow) DimensionScore {
	ds := DimensionScore{Dimension: dim}
	for _, r := range rows {
		if Dimension(r.Capability) != dim {
			continue
		}
		switch r.Verdict {
		case "PASS":
			ds.Pass += r.Count
		case "FAIL":
			ds.Fail += r.Count
		case "ERROR":
			ds.Error += r.Count
		case "SKIPPED":
			switch r.SkipReason {
			case "insufficient_evidence":
				ds.Unknown += r.Count
			case "not_applicable":
				ds.NotApplicable += r.Count
			case "not_tested":
				ds.NotTested += r.Count
			}
		}
	}
	if denom := ds.Pass + ds.Fail + ds.Error + ds.Unknown; denom > 0 {
		ds.PassRate = float64(ds.Pass) / float64(denom)
	}
	return ds
}

// weights are the roadmap's own illustrative starting weights
// (ransomware.txt lines 194-221) -- NOT an industry standard, calibrate
// later against real validation data.
var weights = map[Dimension]float64{
	DimensionPrevention:     0.25,
	DimensionDetection:      0.20,
	DimensionContainment:    0.20,
	DimensionRecovery:       0.25,
	DimensionDataProtection: 0.10,
}

// ScoreRun is the package's one public entry point: pure function, no I/O,
// same input always gives the same output.
func ScoreRun(rows []CoverageRow) RunScore {
	dims := make([]DimensionScore, len(allDimensions))
	byDim := map[Dimension]DimensionScore{}
	for i, d := range allDimensions {
		ds := bucketDimension(d, rows)
		dims[i] = ds
		byDim[d] = ds
	}

	// Weighted average over only the dimensions with at least one
	// evaluated row -- an empty dimension's weight is excluded and the
	// remaining weights are implicitly rescaled by dividing the weighted
	// sum by their own total rather than by 1.0 (spec section C's exact
	// formula).
	var weightedSum, weightTotal float64
	for _, d := range allDimensions {
		ds := byDim[d]
		if ds.Pass+ds.Fail+ds.Error+ds.Unknown == 0 {
			continue
		}
		weightedSum += weights[d] * ds.PassRate
		weightTotal += weights[d]
	}
	var overall float64
	if weightTotal > 0 {
		overall = 100 * weightedSum / weightTotal
	}

	rating := ratingFor(overall)

	gateTriggered := false
	var criticalFailures []string
	if recovery := byDim[DimensionRecovery]; recovery.Fail > 0 {
		gateTriggered = true
		if rating == RatingProtected {
			rating = RatingAtRisk
		}
		criticalFailures = recoveryFailureMessages(rows)
	}

	return RunScore{
		Overall:          overall,
		Rating:           rating,
		Dimensions:       dims,
		CriticalFailures: criticalFailures,
		GateTriggered:    gateTriggered,
	}
}

func ratingFor(overall float64) Rating {
	switch {
	case overall >= 80:
		return RatingProtected
	case overall >= 50:
		return RatingAtRisk
	default:
		return RatingVulnerable
	}
}

// recoveryFailureMessages names the exact technique(s) and count(s) behind
// a triggered Recovery gate -- never finer-grained than the input actually
// supports (CoverageRow is already a technique-level aggregate).
func recoveryFailureMessages(rows []CoverageRow) []string {
	counts := map[string]int{}
	for _, r := range rows {
		if Dimension(r.Capability) == DimensionRecovery && r.Verdict == "FAIL" {
			counts[r.TechniqueID] += r.Count
		}
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic order
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, fmt.Sprintf("Recovery FAILED for %s (%d attempt(s))", id, counts[id]))
	}
	return out
}
