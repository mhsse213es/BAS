package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/killchain"
)

type fakeRuns struct {
	snap runSnapshot
	err  error
}

func (f fakeRuns) ScenarioRun(context.Context, string) (runSnapshot, error) {
	return f.snap, f.err
}

func collectWith(status string) (killchain.StageEvidence, bool, bool, error) {
	x := EngineStageExecutor{Runs: fakeRuns{snap: runSnapshot{ExecutionID: "run-1", Status: status,
		CompletedAt: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}}}
	return x.Collect(context.Background(), "run-1")
}

func TestCollect_NoReaderRefuses(t *testing.T) {
	x := EngineStageExecutor{}
	_, done, failed, err := x.Collect(context.Background(), "run-1")
	if !errors.Is(err, killchain.ErrNoExecutor) || !done || !failed {
		t.Fatalf("done=%v failed=%v err=%v", done, failed, err)
	}
}

func TestCollect_RunningIsNotDone(t *testing.T) {
	for _, s := range []string{"running", "dispatched", "pending"} {
		_, done, failed, err := collectWith(s)
		if err != nil || done || failed {
			t.Fatalf("status %s: done=%v failed=%v err=%v", s, done, failed, err)
		}
	}
}

func TestCollect_FailedAndPartialAreErrors(t *testing.T) {
	for _, s := range []string{"failed", "error", "partial"} {
		_, done, failed, err := collectWith(s)
		if err != nil || !done || !failed {
			t.Fatalf("status %s: done=%v failed=%v err=%v", s, done, failed, err)
		}
	}
}

func TestCollect_UnknownStatusIsAnError(t *testing.T) {
	if _, _, _, err := collectWith("sideways"); err == nil {
		t.Fatalf("an unknown status must not be treated as success")
	}
}

func TestCollect_ReaderErrorIsReturned(t *testing.T) {
	x := EngineStageExecutor{Runs: fakeRuns{err: errors.New("db down")}}
	if _, _, _, err := x.Collect(context.Background(), "run-1"); err == nil {
		t.Fatalf("a reader error must be returned")
	}
}

// A completed run proves dispatch and completion, and nothing more. The stage
// must come out INCONCLUSIVE, with each unproven fact named as missing. It must
// never be a pass.
func TestCollect_CompletedRunIsInconclusiveNotAPass(t *testing.T) {
	ev, done, failed, err := collectWith("completed")
	if err != nil || !done || failed {
		t.Fatalf("done=%v failed=%v err=%v", done, failed, err)
	}
	stage := killchain.StageDef{Key: "identity", ScenarioID: "credential-access",
		Policy: killchain.StagePolicy{ShouldBlock: true}}
	v := killchain.Evaluate(killchain.StageInput{State: killchain.StateCompleted, Policy: stage.Policy, Evidence: &ev})
	if v.Verdict != killchain.VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", v.Verdict)
	}
	joined := ""
	for _, m := range ev.Missing() {
		joined += m + " "
	}
	for _, want := range []string{"prevention.value", "detection.value", "groundTruth.executed"} {
		if !containsWord(joined, want) {
			t.Fatalf("missing list %q must name %s", joined, want)
		}
	}
}

func containsWord(s, w string) bool {
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] == w {
			return true
		}
	}
	return false
}
