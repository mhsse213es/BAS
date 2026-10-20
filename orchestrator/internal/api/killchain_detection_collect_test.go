package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/verification"
)

type fakeAttest struct {
	recs map[string]verification.Record
	err  error
}

func (f fakeAttest) CurrentForRun(context.Context, string) (map[string]verification.Record, error) {
	return f.recs, f.err
}

func collectWithAttest(recs map[string]verification.Record, attErr error) (killchain.StageEvidence, bool, bool, error) {
	x := EngineStageExecutor{
		Runs: fakeRuns{snap: runSnapshot{ExecutionID: "run-1", Status: "completed",
			CompletedAt: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}},
		Attestations: fakeAttest{recs: recs, err: attErr},
	}
	return x.Collect(context.Background(), "run-1")
}

func TestCollectDetection_DetectedAttestationCarriesAlert(t *testing.T) {
	ev, done, failed, err := collectWithAttest(map[string]verification.Record{
		"exp-1": {Result: verification.ResultDetected, AlertID: "alert-3", Provider: "microsoft_sentinel"},
	}, nil)
	if err != nil || !done || failed {
		t.Fatalf("done=%v failed=%v err=%v", done, failed, err)
	}
	if ev.Detection.Value != killchain.DetectionDetected || ev.Detection.AlertID != "alert-3" {
		t.Fatalf("detection = %+v", ev.Detection)
	}
}

// A vendor's not-detected does not carry health or window, so the verdict
// engine must refuse to score it as not-detected.
func TestCollectDetection_NotDetectedNeverClaimsHealth(t *testing.T) {
	ev, _, _, err := collectWithAttest(map[string]verification.Record{
		"exp-1": {Result: verification.ResultNotDetected, Provider: "microsoft_sentinel"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Detection.Value != killchain.DetectionNotDetected || ev.Detection.TelemetryHealth == killchain.TelemetryHealthy {
		t.Fatalf("detection = %+v", ev.Detection)
	}
	if ev.Detection.WindowComplete == killchain.TriYes {
		t.Fatalf("window asserted complete with no evidence")
	}
}

func TestCollectDetection_NoAttestationsIsInconclusive(t *testing.T) {
	ev, _, _, err := collectWithAttest(map[string]verification.Record{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Detection.Value != killchain.DetectionInconclusive {
		t.Fatalf("no attestations must not be read as a result, got %s", ev.Detection.Value)
	}
}

// A failed read is retryable. It must not become a recorded verdict.
func TestCollectDetection_ReadErrorLeavesStageRetryable(t *testing.T) {
	_, done, failed, err := collectWithAttest(nil, errors.New("db down"))
	if err == nil || done || failed {
		t.Fatalf("done=%v failed=%v err=%v; a read error must be retryable", done, failed, err)
	}
}

// Without a reader, detection stays missing, so the verdict names it as a gap.
func TestCollectDetection_NoReaderLeavesDetectionMissing(t *testing.T) {
	x := EngineStageExecutor{Runs: fakeRuns{snap: runSnapshot{ExecutionID: "run-1", Status: "completed"}}}
	ev, _, _, _ := x.Collect(context.Background(), "run-1")
	if ev.Detection.Value != "" {
		t.Fatalf("detection = %q, want missing", ev.Detection.Value)
	}
}
