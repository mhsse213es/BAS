package dbsim

import "testing"

func sr(res RunResult, prev, det DimensionGrade) StoredReport {
	return StoredReport{Result: res, Dimensions: Dimensions{
		Prevention: prev, Detection: det, Response: DimNotExpected,
		Classification: DimNotExpected, Audit: DimNotExpected, Policy: DimNotExpected,
	}}
}

func TestSummarizeUsesSeparateDenominators(t *testing.T) {
	got := Summarize([]StoredReport{
		sr(ResultPass, DimPass, DimPass),
		sr(ResultFail, DimFail, DimPass),
		sr(ResultPass, DimPass, DimNotExpected),
		sr(ResultFail, DimNotExpected, DimFail),
	})
	want := Summary{PreventionBlocked: 2, PreventionAssessable: 3, DetectionCaught: 2, DetectionAssessable: 3}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if got.ResponseTested {
		t.Fatal("response must always be not tested")
	}
}

func TestSummarizeNeverCountsErrorSkippedOrUnverifiedAsPass(t *testing.T) {
	got := Summarize([]StoredReport{
		sr(ResultError, DimPass, DimPass),   // ERROR never enters a numerator
		sr(ResultSkipped, DimPass, DimPass), // nor SKIPPED
		sr(ResultFail, DimUnverifiable, DimUnverifiable),
		sr(ResultFail, DimSkipped, DimNotExpected),
		sr(ResultPass, DimPass, DimNotExpected),
	})
	if got.PreventionBlocked != 1 || got.PreventionAssessable != 1 {
		t.Fatalf("prevention %+v", got)
	}
	if got.DetectionCaught != 0 || got.DetectionAssessable != 0 {
		t.Fatalf("detection %+v", got)
	}
	// ERROR + SKIPPED + the all-unverifiable one.
	if got.UnableToAssess != 3 {
		t.Fatalf("UnableToAssess=%d want 3", got.UnableToAssess)
	}
	if got.ResponseTested {
		t.Fatal("response tested")
	}
}
