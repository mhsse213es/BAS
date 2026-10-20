package api

import (
	"context"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
)

// liveResolver makes every scenario executable and Windows-supported, so the live
// checks reach the dispatch step.
type liveResolver struct{}

func (liveResolver) ResolveExecutable(context.Context, string) (scenario.ExecutableVersion, error) {
	return scenario.ExecutableVersion{Scenario: &scenario.Scenario{
		ID: "s", Name: "s", Executable: true, SupportedOS: []string{"windows"},
	}}, nil
}

func stageIn(mode string) killchain.StageDef {
	return killchain.StageDef{Key: "identity", ScenarioID: "credential-access", Mode: mode}
}

func liveExec(opts stageDispatchOptions, d *fakeDispatch) EngineStageExecutor {
	return EngineStageExecutor{Resolver: liveResolver{}, AgentID: "agent-1", Dispatcher: d, Options: opts,
		OSes: fakeOSReader{os: "windows"}}
}

// fakeOSReader reports one fixed OS for any agent.
type fakeOSReader struct{ os string }

func (f fakeOSReader) AgentOS(context.Context, string) (string, error) { return f.os, nil }

func withLiveFlag(t *testing.T, on bool) {
	t.Helper()
	prev := liveStagesEnabled
	liveStagesEnabled = func() bool { return on }
	t.Cleanup(func() { liveStagesEnabled = prev })
}

// Flag off refuses a live stage even when approved, and nothing is dispatched.
func TestLiveStages_FlagOffRefusesApprovedLiveStage(t *testing.T) {
	withLiveFlag(t, false)
	d := &fakeDispatch{runID: "run-1"}
	_, err := liveExec(stageDispatchOptions{ConfirmLive: true}, d).Start(context.Background(), "c", stageIn("telemetry"))
	if err == nil || !strings.Contains(err.Error(), "disabled on this server") || d.calls != 0 {
		t.Fatalf("err = %v calls = %d, want the disabled refusal and no dispatch", err, d.calls)
	}
}

// Flag on with no approval refuses the stage. Nothing is dispatched.
func TestLiveStages_UnapprovedLiveStageRefused(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-1"}
	_, err := liveExec(stageDispatchOptions{}, d).Start(context.Background(), "c", stageIn("telemetry"))
	if err == nil || !strings.Contains(err.Error(), "campaign approval") || d.calls != 0 {
		t.Fatalf("err = %v calls = %d, want the approval refusal", err, d.calls)
	}
}

// A telemetry stage with the flag on and approval runs, in telemetry mode, with its
// confirmations passed to the run path.
func TestLiveStages_ApprovedTelemetryStageDispatches(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-t"}
	id, err := liveExec(stageDispatchOptions{ConfirmLive: true}, d).Start(context.Background(), "c", stageIn("telemetry"))
	if err != nil || id != "run-t" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if d.gotMode != "telemetry" {
		t.Fatalf("dispatched mode = %q, want telemetry", d.gotMode)
	}
}

// A lab stage needs confirmLab as well as confirmLive.
func TestLiveStages_LabNeedsBothApprovals(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-l"}
	_, err := liveExec(stageDispatchOptions{ConfirmLive: true}, d).Start(context.Background(), "c", stageIn("lab"))
	if err == nil || d.calls != 0 {
		t.Fatalf("lab with only confirmLive: err=%v calls=%d, want refused", err, d.calls)
	}
	_, err = liveExec(stageDispatchOptions{ConfirmLive: true, ConfirmLab: true}, d).Start(context.Background(), "c", stageIn("lab"))
	if err != nil || d.gotMode != "lab" {
		t.Fatalf("lab with both approvals: err=%v mode=%q", err, d.gotMode)
	}
}

// The gate uses the stage's mode, not the executor's. A posture stage runs as posture even
// when the executor carries live approval.
func TestLiveStages_StageModeIsUsedNotExecutorMode(t *testing.T) {
	withLiveFlag(t, false)
	d := &fakeDispatch{runID: "run-p"}
	_, err := liveExec(stageDispatchOptions{Mode: "telemetry", ConfirmLive: true}, d).Start(context.Background(), "c", stageIn("posture"))
	if err != nil || d.gotMode != "posture" {
		t.Fatalf("err=%v mode=%q, want a posture dispatch", err, d.gotMode)
	}
}

// Approval does not override the scenario's own rules. A non-executable scenario is
// refused even when approved and enabled.
func TestLiveStages_ApprovalDoesNotOverrideScenarioRules(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-x"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true}, d)
	x.Resolver = fakeResolverNotExecutable{}
	_, err := x.Start(context.Background(), "c", stageIn("telemetry"))
	if err == nil || !strings.Contains(err.Error(), "does not support live execution") || d.calls != 0 {
		t.Fatalf("err=%v calls=%d, want the scenario refusal and no dispatch", err, d.calls)
	}
}

type fakeResolverNotExecutable struct{}

func (fakeResolverNotExecutable) ResolveExecutable(context.Context, string) (scenario.ExecutableVersion, error) {
	return scenario.ExecutableVersion{Scenario: &scenario.Scenario{ID: "s", Name: "s", SupportedOS: []string{"windows"}}}, nil
}
