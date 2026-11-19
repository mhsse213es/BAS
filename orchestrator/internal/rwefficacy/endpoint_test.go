package rwefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
)

func TestEndpointOnly_UngradedStepsAreListed(t *testing.T) {
	rows := []db.RWAttemptRow{
		{TechniqueID: "T1486", Action: "a", Capability: "detection", Verdict: controlval.VerdictSkipped, SkipReason: controlval.SkipNotTested},
		{TechniqueID: "T1003.001", Action: "b", Capability: "detection", Verdict: controlval.VerdictPass},
	}
	steps := []EndpointStep{
		{TechniqueID: "T1486", StepName: "encrypt", Result: "fail"},
		{TechniqueID: "T1003.001", StepName: "lsass probe", Result: "pass"},
		{TechniqueID: "T9999", StepName: "no rows at all", Result: "pass"},
	}
	got := EndpointOnly(rows, steps)
	if len(got) != 2 || got[0].TechniqueID != "T1486" || got[1].TechniqueID != "T9999" {
		t.Fatalf("want T1486 and T9999 in order, got %+v", got)
	}
}

func TestEndpointOnly_GradedTechniqueIsExcludedEvenWithSkippedRows(t *testing.T) {
	rows := []db.RWAttemptRow{
		{TechniqueID: "T1490", Action: "a", Capability: "detection", Verdict: controlval.VerdictSkipped, SkipReason: controlval.SkipNotTested},
		{TechniqueID: "T1490", Action: "a", Capability: "containment", Verdict: controlval.VerdictFail},
	}
	got := EndpointOnly(rows, []EndpointStep{{TechniqueID: "T1490", Result: "fail"}})
	if len(got) != 0 {
		t.Fatalf("a technique with a graded FAIL must not be endpoint-only, got %+v", got)
	}
}

func TestEndpointOnly_NoStepsReturnsEmpty(t *testing.T) {
	if got := EndpointOnly(nil, nil); len(got) != 0 {
		t.Fatalf("got %+v, want empty", got)
	}
}
