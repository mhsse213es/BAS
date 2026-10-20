package api

import (
	"context"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/killchain"
)

func liveStageExec(mode string, d *fakeDispatch) EngineStageExecutor {
	return EngineStageExecutor{Resolver: resolverOK{}, AgentID: "agent-1", Dispatcher: d,
		Options: stageDispatchOptions{Mode: mode}}
}

func withLiveFlag(t *testing.T, on bool) {
	t.Helper()
	prev := liveStagesEnabled
	liveStagesEnabled = func() bool { return on }
	t.Cleanup(func() { liveStagesEnabled = prev })
}

// The flag is off by default. A live stage is refused with the flag named as the
// cause, and nothing is dispatched.
func TestLiveStages_FlagOffRefusesLiveStage(t *testing.T) {
	withLiveFlag(t, false)
	d := &fakeDispatch{runID: "run-1"}
	_, err := liveStageExec("telemetry", d).Start(context.Background(), "c", dispatchStage())
	if err == nil || !strings.Contains(err.Error(), "disabled on this server") {
		t.Fatalf("err = %v, want the disabled refusal", err)
	}
	if d.calls != 0 {
		t.Fatalf("a refused live stage was dispatched")
	}
}

// Turning the flag on does not let a live stage through yet. Approval is not
// built, so there is no confirmation to check, and dispatch must not run.
func TestLiveStages_FlagOnStillRefusesUntilApprovalExists(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-1"}
	_, err := liveStageExec("lab", d).Start(context.Background(), "c", dispatchStage())
	if err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("err = %v, want the approval refusal", err)
	}
	if d.calls != 0 {
		t.Fatalf("a live stage with no approval was dispatched")
	}
}

// Posture is unaffected by the flag.
func TestLiveStages_PostureUnaffectedByFlag(t *testing.T) {
	withLiveFlag(t, false)
	d := &fakeDispatch{runID: "run-9"}
	id, err := liveStageExec("posture", d).Start(context.Background(), "c", dispatchStage())
	if err != nil || id != "run-9" || d.calls != 1 {
		t.Fatalf("id=%q err=%v calls=%d", id, err, d.calls)
	}
}

var _ = killchain.VerdictInconclusive
