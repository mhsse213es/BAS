package dlpcorrelate

import "testing"

func fourStageChain() CorrelationChain {
	return CorrelationChain{
		ID:   "TEST-CHAIN",
		Name: "test chain",
		Stages: []StageDefinition{
			{Label: "stage 1", Dimension: "DIM1"},
			{Label: "stage 2", Dimension: "DIM2"},
			{Label: "stage 3", Dimension: "DIM3"},
			{Label: "stage 4", Dimension: "DIM4"},
		},
	}
}

func TestEvaluateCorrelationChain_AllContinue_NoSkips(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageContinues},
		{StageOrder: 3, Label: "stage 3", Dimension: "DIM3", Outcome: StageContinues},
		{StageOrder: 4, Label: "stage 4", Dimension: "DIM4", Outcome: StageContinues},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 4 {
		t.Fatalf("StageResults len = %d, want 4", len(got.StageResults))
	}
	for i, r := range got.StageResults {
		if r.StageSkipped {
			t.Errorf("stage %d: StageSkipped = true, want false", i+1)
		}
	}
	if got.AnyFailed || got.AnyNotTested || got.StoppedAtLabel != "" {
		t.Errorf("got = %+v, want a clean run", got)
	}
}

func TestEvaluateCorrelationChain_TwoOfFourReached_SkipsStage3And4(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageCaught},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 4 {
		t.Fatalf("StageResults len = %d, want 4", len(got.StageResults))
	}
	if got.StageResults[2].StageSkipped != true || got.StageResults[2].Label != "stage 3" {
		t.Errorf("stage 3 = %+v, want skipped with label %q", got.StageResults[2], "stage 3")
	}
	if got.StageResults[3].StageSkipped != true || got.StageResults[3].Label != "stage 4" {
		t.Errorf("stage 4 = %+v, want skipped with label %q", got.StageResults[3], "stage 4")
	}
	if got.StoppedAtLabel != "stage 2" {
		t.Errorf("StoppedAtLabel = %q, want %q", got.StoppedAtLabel, "stage 2")
	}
}

func TestEvaluateCorrelationChain_FailureAtStage1DoesNotStopChain(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageFailed, Reason: "confirmed failure"},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageContinues},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].StageSkipped {
		t.Error("stage 2 must not be skipped just because stage 1 failed -- failure does not stop the chain")
	}
	if got.StageResults[1].Outcome != StageContinues {
		t.Errorf("stage 2 outcome = %v, want StageContinues (caller supplied it, not re-derived)", got.StageResults[1].Outcome)
	}
}

func TestEvaluateCorrelationChain_AnyFailedStaysTrueEvenAfterLaterCleanStage(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageFailed, Reason: "confirmed failure"},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageContinues},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must stay true: stage 1 failed, and a later clean stage must never un-set it")
	}
}

func TestEvaluateCorrelationChain_CaughtStopsChain(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageCaught, Reason: "blocked"},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.StageResults[2].StageSkipped {
		t.Error("stage 3 must be skipped after stage 2 caught the violation")
	}
}

func TestEvaluateCorrelationChain_TooManyReachedIsError(t *testing.T) {
	reached := make([]StageResult, 5)
	for i := range reached {
		reached[i] = StageResult{StageOrder: i + 1, Outcome: StageContinues}
	}
	_, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err == nil {
		t.Error("expected an error when reached has more entries than chain.Stages")
	}
}

func TestEvaluateCorrelationChain_OutOfOrderStageOrderIsError(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 2, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
	}
	_, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err == nil {
		t.Error("expected an error when reached[0].StageOrder does not match its position (1)")
	}
}
