package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

type fakeGT struct {
	rec   db.GroundTruthRecord
	found bool
	err   error
}

func (f fakeGT) GroundTruthForRun(context.Context, string) (db.GroundTruthRecord, bool, error) {
	return f.rec, f.found, f.err
}

func collectWithGT(gt groundTruthReader) (killchain.StageEvidence, bool, bool, error) {
	x := EngineStageExecutor{
		Runs: fakeRuns{snap: runSnapshot{ExecutionID: "run-1", Status: "completed",
			CompletedAt: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}},
		GroundTruth: gt,
	}
	return x.Collect(context.Background(), "run-1")
}

func TestCollectGroundTruth_IndependentRecordIsUsed(t *testing.T) {
	ev, _, _, err := collectWithGT(fakeGT{found: true, rec: db.GroundTruthRecord{
		Source: "sysmon-event-1", Executed: killchain.TriYes, Reference: "host:evt-123"}})
	if err != nil {
		t.Fatal(err)
	}
	if ev.GroundTruth.Source != "sysmon-event-1" || ev.GroundTruth.Executed != killchain.TriYes {
		t.Fatalf("ground truth = %+v", ev.GroundTruth)
	}
}

// With no independent record, execution is a named gap and is never assumed.
func TestCollectGroundTruth_NoRecordLeavesExecutionMissing(t *testing.T) {
	ev, _, _, err := collectWithGT(fakeGT{found: false})
	if err != nil {
		t.Fatal(err)
	}
	if ev.GroundTruth.Executed != "" {
		t.Fatalf("executed = %q, want missing", ev.GroundTruth.Executed)
	}
}

func TestCollectGroundTruth_ReadErrorLeavesStageRetryable(t *testing.T) {
	_, done, failed, err := collectWithGT(fakeGT{err: errors.New("db down")})
	if err == nil || done || failed {
		t.Fatalf("done=%v failed=%v err=%v; a read error must be retryable", done, failed, err)
	}
}

func TestCollectGroundTruth_NilReaderLeavesExecutionMissing(t *testing.T) {
	ev, _, _, _ := collectWithGT(nil)
	if ev.GroundTruth.Executed != "" {
		t.Fatalf("executed = %q, want missing", ev.GroundTruth.Executed)
	}
}
