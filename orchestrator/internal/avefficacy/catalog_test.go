package avefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

func TestAudspectAVAssessmentScenario_ValidatesAgainstRealCatalog(t *testing.T) {
	scenario, err := AudspectAVAssessmentScenario()
	if err != nil {
		t.Fatalf("AudspectAVAssessmentScenario: %v", err)
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		t.Errorf("ValidateAgainstCatalog: %v", err)
	}
}

// Review Focus: the real seed scenario must resolve to Fail (the
// deliberate AV-PERSIST-002 bypass), with Fail winning over the two
// deliberately untested vectors -- the exact same precedence
// wafassessment's own seed scenario proves, now against the real AV
// catalog and real avefficacy evaluation chain end to end.
func TestEvaluateScenarioBySlug_AVAssessment_RealFailOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("av-assessment")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-ASSESSMENT-001" {
		t.Errorf("scenario.ID = %q, want AV-ASSESSMENT-001", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (AV-PERSIST-002's deliberate bypass must fail the scenario)", result.Outcome, ScenarioFail)
	}
	var sawGap bool
	for _, o := range result.VectorOutcomes {
		if o.VectorID == "AV-PERSIST-002" && o.Finding == avval.FindingConfirmedGap {
			sawGap = true
		}
	}
	if !sawGap {
		t.Error("AV-PERSIST-002 did not resolve to FindingConfirmedGap")
	}
	if len(result.UntestedVectorIDs) != 2 {
		t.Errorf("UntestedVectorIDs = %v, want 2 entries (AV-FILE-002, AV-SCRIPT-002)", result.UntestedVectorIDs)
	}
}

func TestEvaluateScenarioBySlug_UnknownSlug_Error(t *testing.T) {
	if _, _, err := EvaluateScenarioBySlug("does-not-exist"); err == nil {
		t.Fatal("want error for an unknown slug, got nil")
	}
}
