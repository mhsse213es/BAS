package dbsim

import "testing"

func TestSummarizeEmptyAndAllPass(t *testing.T) {
	if got := Summarize(nil); got != (Summary{}) {
		t.Fatalf("empty: %+v", got)
	}
	got := Summarize([]StoredReport{sr(ResultPass, DimPass, DimPass), sr(ResultPass, DimPass, DimPass)})
	want := Summary{PreventionBlocked: 2, PreventionAssessable: 2, DetectionCaught: 2, DetectionAssessable: 2}
	if got != want {
		t.Fatalf("all pass: %+v", got)
	}
}

func TestSummarizeTreatsEmptyGradeAsUnverifiable(t *testing.T) {
	r := StoredReport{Result: ResultFail, Dimensions: Dimensions{Prevention: "", Detection: DimNotExpected}}
	got := Summarize([]StoredReport{r})
	if got.UnableToAssess != 1 || got.PreventionAssessable != 0 || got.PreventionBlocked != 0 {
		t.Fatalf("%+v", got)
	}
}
