package dbsim

// Summary is the run-level roll-up with deliberately separate denominators.
// It never reads or writes any security score.
type Summary struct {
	PreventionBlocked    int
	PreventionAssessable int
	DetectionCaught      int
	DetectionAssessable  int
	UnableToAssess       int
	// ResponseTested is always false: response is not tested by this product.
	ResponseTested bool
}

// Summarize computes the summary. Only a prevention/detection dimension
// graded pass or fail is assessable; only pass is a numerator, and never from
// an ERROR or SKIPPED scenario. unverifiable, skipped and not_expected are
// never assessable and never a numerator.
func Summarize(reports []StoredReport) Summary {
	var s Summary
	for _, r := range reports {
		if r.Result == ResultError || r.Result == ResultSkipped {
			s.UnableToAssess++
			continue
		}
		d := r.Dimensions
		if d.Prevention == DimPass || d.Prevention == DimFail {
			s.PreventionAssessable++
			if d.Prevention == DimPass {
				s.PreventionBlocked++
			}
		}
		if d.Detection == DimPass || d.Detection == DimFail {
			s.DetectionAssessable++
			if d.Detection == DimPass {
				s.DetectionCaught++
			}
		}
		if noneEstablished(d) {
			s.UnableToAssess++
		}
	}
	return s
}

// noneEstablished: no dimension was established (pass or fail) and at least
// one was left unverifiable.
func noneEstablished(d Dimensions) bool {
	unver := false
	for _, g := range []DimensionGrade{d.Prevention, d.Detection, d.Response, d.Classification, d.Audit, d.Policy} {
		switch g {
		case DimPass, DimFail:
			return false
		case DimUnverifiable:
			unver = true
		}
	}
	return unver
}
