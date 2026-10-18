package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/dlpclassify"
	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateCampaign01_CleanRun_Stage4AlwaysNotTested(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 4 {
		t.Fatalf("StageResults len = %d, want 4", len(got.StageResults))
	}
	stage4 := got.StageResults[3]
	if stage4.Outcome != StageNotTested {
		t.Errorf("stage 4 outcome = %v, want StageNotTested even on a clean run", stage4.Outcome)
	}
	if got.AnyNotTested != true {
		t.Error("AnyNotTested must be true: stage 4 is permanently not tested")
	}
}

func TestEvaluateCampaign01_Match_StageCaughtStopsChain(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[2].Outcome != StageCaught {
		t.Errorf("stage 3 outcome = %v, want StageCaught", got.StageResults[2].Outcome)
	}
	if !got.StageResults[3].StageSkipped {
		t.Error("stage 4 should be marked skipped (chain stopped at stage 3's Caught) even though it is also always NotTested conceptually -- EvaluateCorrelationChain's own skip logic takes precedence once the chain stops")
	}
}

func TestEvaluateCampaign01_Mismatch_MapsToStageFailedNotCaught(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Mismatch, "operation succeeded despite expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[2].Outcome != StageFailed {
		t.Errorf("stage 3 outcome = %v, want StageFailed for a Mismatch (disclosure succeeded)", got.StageResults[2].Outcome)
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true when stage 3 resolves Mismatch")
	}
}

func TestEvaluateCampaign01_MissingEvidence_MapsToInconclusiveAndStopsChain(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.MissingEvidence, "no sink evidence")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[2].Outcome != StageInconclusive {
		t.Errorf("stage 3 outcome = %v, want StageInconclusive for MissingEvidence", got.StageResults[2].Outcome)
	}
}

func TestEvaluateCampaign01_MisclassifiedStage1_MapsToFailedAndStage2StillRuns(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeFalseNegative, Reason: "sensitive data not flagged"}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
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

func TestEvaluateCampaign01_LabelInconclusive_StopsChainBeforeStage3(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeInconclusive, Reason: "no label evidence found"}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].Outcome != StageInconclusive {
		t.Errorf("stage 2 outcome = %v, want StageInconclusive", got.StageResults[1].Outcome)
	}
	if !got.StageResults[2].StageSkipped {
		t.Error("stage 3 must be skipped: stage 2 was inconclusive")
	}
}
