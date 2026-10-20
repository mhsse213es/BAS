package killchain

import (
	"strings"
	"testing"
)

// A source names why it could not prove a stage. The verdict must carry those
// reasons, not only the bare name of the missing field.
func TestVerdict_SourceGapsAreReportedAsReasons(t *testing.T) {
	ev := StageEvidence{
		SourceGaps: []string{"process creation auditing is disabled on WS-01; no 4688 record is not evidence"},
	}
	v := Evaluate(StageInput{State: StateCompleted, Evidence: &ev})
	if v.Verdict != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", v.Verdict)
	}
	if !containsSub(v.Reasons, "process creation auditing is disabled on WS-01") {
		t.Fatalf("reasons = %v, want the source gap", v.Reasons)
	}
	if !containsSub(v.Reasons, "missing evidence") {
		t.Fatalf("reasons = %v, want the missing fields still named", v.Reasons)
	}
}

func TestVerdict_NoSourceGapsKeepsPlainMissingReason(t *testing.T) {
	ev := StageEvidence{}
	v := Evaluate(StageInput{State: StateCompleted, Evidence: &ev})
	if containsSub(v.Reasons, "auditing") {
		t.Fatalf("reasons = %v, no gap should appear", v.Reasons)
	}
}

func containsSub(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}
