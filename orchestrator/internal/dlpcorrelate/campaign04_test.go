package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/dlpclassify"
	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateCampaign04_CleanRun_Stage3AlwaysNotTested(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	got, err := EvaluateCampaign04(classVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 3 {
		t.Fatalf("StageResults len = %d, want 3", len(got.StageResults))
	}
	stage3 := got.StageResults[2]
	if stage3.Outcome != StageNotTested || !stage3.StageSkipped {
		t.Errorf("stage 3 = %+v, want StageNotTested+StageSkipped even on a clean run", stage3)
	}
	if got.AnyNotTested != true {
		t.Error("AnyNotTested must be true: stage 3 is permanently not tested")
	}
}

func TestEvaluateCampaign04_Match_StageCaughtStopsChain(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	got, err := EvaluateCampaign04(classVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].Outcome != StageCaught {
		t.Errorf("stage 2 outcome = %v, want StageCaught", got.StageResults[1].Outcome)
	}
}

func TestEvaluateCampaign04_Mismatch_MapsToStageFailedViaExistingHelper(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	got, err := EvaluateCampaign04(classVerdict, reporting.Mismatch, "export succeeded despite expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].Outcome != StageFailed {
		t.Errorf("stage 2 outcome = %v, want StageFailed for a Mismatch", got.StageResults[1].Outcome)
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true")
	}
}

func TestEvaluateCampaign04_MisclassifiedStage1_StillRunsStage2(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeFalseNegative, Reason: "sensitive dataset record not flagged"}
	got, err := EvaluateCampaign04(classVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[0].Outcome != StageFailed {
		t.Errorf("stage 1 outcome = %v, want StageFailed for a FalseNegative", got.StageResults[0].Outcome)
	}
	if got.StageResults[1].StageSkipped {
		t.Error("stage 2 must still run after stage 1's failure -- a failure does not stop the chain")
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true")
	}
}

func TestCampaign04DepartingEmployeeDataExposure_StageDimensionsMatchCampaign01Vocabulary(t *testing.T) {
	stages := Campaign04DepartingEmployeeDataExposure.Stages
	if len(stages) != 3 {
		t.Fatalf("Stages len = %d, want 3", len(stages))
	}
	if stages[0].Dimension != "DLP-CLS" {
		t.Errorf("stage 1 Dimension = %q, want %q", stages[0].Dimension, "DLP-CLS")
	}
	if stages[1].Dimension != "DLP-ENF" {
		t.Errorf("stage 2 Dimension = %q, want %q", stages[1].Dimension, "DLP-ENF")
	}
}
