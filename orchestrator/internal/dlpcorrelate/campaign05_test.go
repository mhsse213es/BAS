package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/reporting"
)

func cleanCampaign05Evidence() Campaign05Evidence {
	return Campaign05Evidence{
		EnforcementComparison: reporting.Match,
		EnforcementReason:     "observed block matches expected Block",
		ConsoleComparison:     reporting.Match,
		ConsoleReason:         "console event matches expected action",
		SIEMVerdict:           detectverify.VerdictDetected,
		TicketAttempted:       true,
		TicketID:              "INC-1001",
	}
}

func TestEvaluateCampaign05_CleanRun_PermanentGapsStayNotTested(t *testing.T) {
	got, err := EvaluateCampaign05(cleanCampaign05Evidence())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 6 {
		t.Fatalf("StageResults len = %d, want 6", len(got.StageResults))
	}
	for i := 0; i < 4; i++ {
		if got.StageResults[i].Outcome != StageContinues {
			t.Errorf("stage %d outcome = %v, want StageContinues", i+1, got.StageResults[i].Outcome)
		}
	}
	for i := 4; i < 6; i++ {
		if got.StageResults[i].Outcome != StageNotTested || !got.StageResults[i].StageSkipped {
			t.Errorf("stage %d = %+v, want permanent StageNotTested+StageSkipped", i+1, got.StageResults[i])
		}
	}
	if !got.AnyNotTested {
		t.Error("AnyNotTested must be true: assignment and response time are never measurable")
	}
	if got.AnyFailed {
		t.Error("AnyFailed must be false on a clean run")
	}
}

func TestEvaluateCampaign05_EnforcementMatch_DoesNotStopChain(t *testing.T) {
	got, err := EvaluateCampaign05(cleanCampaign05Evidence())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].StageSkipped {
		t.Error("a successful block must not halt detection-to-response verification; stage 2 must run")
	}
}

func TestEvaluateCampaign05_EnforcementMismatch_FailsButContinues(t *testing.T) {
	ev := cleanCampaign05Evidence()
	ev.EnforcementComparison = reporting.Mismatch
	got, err := EvaluateCampaign05(ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[0].Outcome != StageFailed {
		t.Errorf("stage 1 outcome = %v, want StageFailed", got.StageResults[0].Outcome)
	}
	if got.StageResults[3].StageSkipped {
		t.Error("a confirmed enforcement failure must not stop incident-creation verification")
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true")
	}
}

func TestEvaluateCampaign05_ConsoleMissingEvidence_StopsChain(t *testing.T) {
	ev := cleanCampaign05Evidence()
	ev.ConsoleComparison = reporting.MissingEvidence
	got, err := EvaluateCampaign05(ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].Outcome != StageInconclusive {
		t.Errorf("stage 2 outcome = %v, want StageInconclusive for absent console evidence", got.StageResults[1].Outcome)
	}
	if !got.StageResults[2].StageSkipped {
		t.Error("stage 3 must be skipped after an inconclusive console stage")
	}
}

func TestEvaluateCampaign05_SIEMNotDetected_IsInconclusiveNotFailed(t *testing.T) {
	ev := cleanCampaign05Evidence()
	ev.SIEMVerdict = detectverify.VerdictNotDetected
	got, err := EvaluateCampaign05(ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[2].Outcome != StageInconclusive {
		t.Errorf("stage 3 outcome = %v, want StageInconclusive: absence in a window may be delayed ingestion (dlp.txt §6)", got.StageResults[2].Outcome)
	}
	if got.AnyFailed {
		t.Error("NotDetected must not be recorded as a confirmed failure")
	}
	if !got.StageResults[3].StageSkipped {
		t.Error("stage 4 must be skipped after an inconclusive SIEM stage")
	}
}

func TestEvaluateCampaign05_TicketNotAttempted_StopsAtIncidentCreation(t *testing.T) {
	ev := cleanCampaign05Evidence()
	ev.TicketAttempted = false
	ev.TicketID = ""
	got, err := EvaluateCampaign05(ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[3].Outcome != StageInconclusive {
		t.Errorf("stage 4 outcome = %v, want StageInconclusive when no creation was attempted", got.StageResults[3].Outcome)
	}
}

func TestEvaluateCampaign05_TicketAttemptedWithNoID_IsFailedAndContinues(t *testing.T) {
	ev := cleanCampaign05Evidence()
	ev.TicketID = ""
	got, err := EvaluateCampaign05(ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[3].Outcome != StageFailed {
		t.Errorf("stage 4 outcome = %v, want StageFailed for an attempt that returned no ticket ID", got.StageResults[3].Outcome)
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true")
	}
	if got.StageResults[4].Outcome != StageNotTested {
		t.Errorf("stage 5 outcome = %v, want permanent StageNotTested", got.StageResults[4].Outcome)
	}
}

func TestCampaign05DetectionToResponse_StageDimensions(t *testing.T) {
	stages := Campaign05DetectionToResponse.Stages
	want := []string{"DLP-ENF", "DLP-TEL", "DLP-TEL", "DLP-RESP", "DLP-RESP", "DLP-RESP"}
	if len(stages) != len(want) {
		t.Fatalf("Stages len = %d, want %d", len(stages), len(want))
	}
	for i, d := range want {
		if stages[i].Dimension != d {
			t.Errorf("stage %d Dimension = %q, want %q", i+1, stages[i].Dimension, d)
		}
	}
}
