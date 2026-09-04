package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExecutionAttemptJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	ea := ExecutionAttempt{
		ID:                 "attempt-1",
		Source:              ExecutionSourceART,
		Granularity:         GranularityRun,
		SourceExecutionID:   "run-1",
		SourceAttemptID:     "run-1",
		Status:              ExecutionAttemptCompleted,
		CreatedAt:           now,
		DispatchQueuedAt:    &now,
		DispatchSentAt:      &now,
		CompletedAt:         &now,
	}
	data, err := json.Marshal(ea)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ExecutionAttempt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != ea.ID || got.Status != ea.Status {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, ea)
	}
}

func TestSkipReasonConstants(t *testing.T) {
	reasons := []SkipReason{
		SkipReasonConditionFalse,
		SkipReasonPrerequisiteUnsatisfied,
		SkipReasonCancelledBeforeDispatch,
		SkipReasonDependencyFailed,
	}
	for _, r := range reasons {
		if r == "" {
			t.Fatal("skip reason constant must not be empty string")
		}
	}
}
