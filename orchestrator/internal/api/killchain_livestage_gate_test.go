package api

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
)

// auditCall is one recorded audit event from a live stage start.
type auditCall struct {
	action, resource, outcome string
	detail                    map[string]any
}

func recordAudit(calls *[]auditCall) stageAuditFunc {
	return func(_ context.Context, action, resource string, detail map[string]any, outcome string) {
		*calls = append(*calls, auditCall{action, resource, outcome, detail})
	}
}

// A refused live stage is audited as denied, with the gate that refused it.
func TestLiveStageAudit_RefusalIsAudited(t *testing.T) {
	withLiveFlag(t, false)
	var calls []auditCall
	d := &fakeDispatch{runID: "run-1"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true}, d)
	x.Audit = recordAudit(&calls)
	if _, err := x.Start(context.Background(), "camp-1", stageIn("telemetry")); err == nil {
		t.Fatal("expected a refusal")
	}
	if len(calls) != 1 || calls[0].action != "killchain.stage.refused" || calls[0].outcome != "denied" {
		t.Fatalf("audit = %+v, want one denied refusal", calls)
	}
	if !strings.Contains(fmt.Sprint(calls[0].detail["gate"]), "disabled") {
		t.Fatalf("refusal detail = %v, want the gate reason", calls[0].detail)
	}
}

// An approved live start is audited as success, with the approver and the run id.
func TestLiveStageAudit_StartIsAudited(t *testing.T) {
	withLiveFlag(t, true)
	var calls []auditCall
	who := "bob"
	d := &fakeDispatch{runID: "run-42"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true, Reason: "CHG-7", InitiatedBy: &who}, d)
	x.Audit = recordAudit(&calls)
	if _, err := x.Start(context.Background(), "camp-1", stageIn("telemetry")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].action != "killchain.stage.start" || calls[0].outcome != "success" {
		t.Fatalf("audit = %+v, want one success start", calls)
	}
	if calls[0].detail["runId"] != "run-42" || calls[0].detail["approvedBy"] != "bob" || calls[0].detail["reason"] != "CHG-7" {
		t.Fatalf("start detail = %v", calls[0].detail)
	}
}

// Posture starts are not audited as live stages.
func TestLiveStageAudit_PostureNotAudited(t *testing.T) {
	var calls []auditCall
	d := &fakeDispatch{runID: "run-p"}
	x := liveExec(stageDispatchOptions{}, d)
	x.Audit = recordAudit(&calls)
	if _, err := x.Start(context.Background(), "camp-1", stageIn("posture")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("posture produced audit events: %+v", calls)
	}
}

// The agent's OS is checked at start. A mismatch refuses the stage before dispatch.
func TestLiveStageOS_MismatchAtStartRefused(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-1"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true}, d)
	x.OSes = fakeOSReader{os: "linux"}
	_, err := x.Start(context.Background(), "camp-1", stageIn("telemetry"))
	if err == nil || !strings.Contains(err.Error(), "OS mismatch") || d.calls != 0 {
		t.Fatalf("err=%v calls=%d, want the OS refusal and no dispatch", err, d.calls)
	}
}

// An unknown agent OS refuses the live stage, because the check cannot run.
func TestLiveStageOS_UnknownOSRefused(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-1"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true}, d)
	x.OSes = fakeOSReader{os: ""}
	_, err := x.Start(context.Background(), "camp-1", stageIn("telemetry"))
	if err == nil || !strings.Contains(err.Error(), "unknown") || d.calls != 0 {
		t.Fatalf("err=%v calls=%d, want the unknown-OS refusal", err, d.calls)
	}
}

// With no OS reader wired, a live stage is refused rather than run unchecked.
func TestLiveStageOS_NoReaderRefused(t *testing.T) {
	withLiveFlag(t, true)
	d := &fakeDispatch{runID: "run-1"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true}, d)
	x.OSes = nil
	if _, err := x.Start(context.Background(), "camp-1", stageIn("telemetry")); err == nil || d.calls != 0 {
		t.Fatalf("err=%v calls=%d, want a refusal and no dispatch", err, d.calls)
	}
}

// A window that closed after approval refuses the stage at start. The window is set to
// twelve hours before now, so it is closed at any time of day.
func TestLiveStageWindow_ClosedAtStartRefused(t *testing.T) {
	withLiveFlag(t, true)
	past := time.Now().Add(-12 * time.Hour)
	end := past.Add(time.Minute)
	window := fmt.Sprintf("%02d:%02d-%02d:%02d", past.Hour(), past.Minute(), end.Hour(), end.Minute())
	res := windowResolver{window: window}
	d := &fakeDispatch{runID: "run-1"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true}, d)
	x.Resolver = res
	_, err := x.Start(context.Background(), "camp-1", stageIn("telemetry"))
	if err == nil || !strings.Contains(err.Error(), "execution window") || d.calls != 0 {
		t.Fatalf("err=%v calls=%d, want the window refusal and no dispatch", err, d.calls)
	}
}

// An injected clock controls the window, so the same window passes when the clock says
// it is open.
func TestLiveStageWindow_UsesInjectedClock(t *testing.T) {
	withLiveFlag(t, true)
	window := "09:00-10:00"
	inside := time.Date(2026, 10, 20, 9, 30, 0, 0, time.Local)
	d := &fakeDispatch{runID: "run-ok"}
	x := liveExec(stageDispatchOptions{ConfirmLive: true}, d)
	x.Resolver = windowResolver{window: window}
	x.Now = func() time.Time { return inside }
	if _, err := x.Start(context.Background(), "camp-1", stageIn("telemetry")); err != nil {
		t.Fatalf("inside the window refused: %v", err)
	}
}

type windowResolver struct{ window string }

func (w windowResolver) ResolveExecutable(context.Context, string) (scenario.ExecutableVersion, error) {
	return scenario.ExecutableVersion{Scenario: &scenario.Scenario{
		ID: "s", Name: "s", Executable: true, SupportedOS: []string{"windows"},
		LivePolicy: &scenario.LivePolicy{ExecutionWindow: w.window},
	}}, nil
}

// The refactor guard: the single-run handler and the campaign stage path both reach
// checkLiveGates, so a future edit cannot quietly drop one of them.
func TestLiveGates_BothCallersReachSharedCheck(t *testing.T) {
	for _, f := range []string{"handlers.go", "killchain_executor.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "checkLiveGates(") {
			t.Fatalf("%s does not call checkLiveGates", f)
		}
	}
}
