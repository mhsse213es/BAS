package rwscore

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
