package k8sscenario

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// eventTypes returns the audit event types in the order they were written.
func eventTypes(events []Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return out
}

// outcomeOf returns the single outcome event, failing the test if there is not exactly one.
func outcomeOf(t *testing.T, events []Event) Event {
	t.Helper()
	var found []Event
	for _, e := range events {
		if e.Type == EventOutcome {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one outcome event, got %d", len(found))
	}
	return found[0]
}

// A run cancelled while its snapshot is being recorded writes nothing to the cluster. The audit trail is exactly:
// requested, snapshot, outcome. The outcome shows the verified restore and the stop reason as separate fields.
func TestLifecycleAudit_CancelledRunSequence(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	// The run and its approval carry the authorization and customer, as a planned Controlled run does.
	req.AuthorizationID, req.CustomerRef = "k8sa-1", "cust-1"
	appr, _, _ := store.Get("appr-cm")
	appr.AuthorizationID, appr.CustomerRef = "k8sa-1", "cust-1"
	_ = store.Put(appr)
	var eng *Engine
	au := &hookAudit{onWrite: func(e Event) error {
		if e.Type == EventSnapshot {
			eng.Cancel(req.RunID)
		}
		return nil
	}}
	cfg := testConfig(fc, au, &recordAlert{}, store)
	cfg.ControlledGate = allowGate
	eng = NewEngine(cfg)
	res := eng.Run(context.Background(), req)
	if res.State != StateCancelled {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCancelled)
	}
	want := []string{EventRequested, EventSnapshot, EventOutcome}
	if got := eventTypes(au.events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit sequence = %v, want %v", got, want)
	}
	out := outcomeOf(t, au.events)
	if out.Fields["state"] != string(StateCancelled) || out.Fields["rollback"] != "verified" {
		t.Errorf("outcome state/rollback = %q/%q, want CANCELLED/verified", out.Fields["state"], out.Fields["rollback"])
	}
	if !strings.Contains(out.Fields["stop"], ErrCancelledByOperator.Error()) {
		t.Errorf("outcome stop = %q, want the operator cancellation", out.Fields["stop"])
	}
	for _, k := range []string{"clusterId", "authorizationId", "customerRef", "approval", "requester"} {
		if out.Fields[k] == "" {
			t.Errorf("outcome must carry %s", k)
		}
	}
}

// A stop whose rollback cannot be verified: the outcome says the rollback failed and names the stop. It is never
// recorded as a verified restore.
func TestLifecycleAudit_FailedRollbackAfterStopIsRecorded(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	var eng *Engine
	fc.onSetData = func() {
		eng.Cancel(req.RunID)
		fc.failSetData = true
	}
	au := &hookAudit{}
	cfg := testConfig(fc, au, &recordAlert{}, store)
	cfg.ControlledGate = allowGate
	eng = NewEngine(cfg)
	res := eng.Run(context.Background(), req)
	if res.State != StateCleanupFailed {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCleanupFailed)
	}
	out := outcomeOf(t, au.events)
	if out.Fields["rollback"] != "failed" {
		t.Errorf("outcome rollback = %q, want failed", out.Fields["rollback"])
	}
	if !strings.Contains(out.Fields["stop"], ErrCancelledByOperator.Error()) {
		t.Errorf("outcome stop = %q, want the operator cancellation", out.Fields["stop"])
	}
	if out.Fields["state"] != string(StateCleanupFailed) {
		t.Errorf("outcome state = %q, want CLEANUP_FAILED", out.Fields["state"])
	}
}

// The time limit is named in the outcome as its own stop reason, not left to be read from the message.
func TestLifecycleAudit_TimeLimitIsNamedInTheOutcome(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	au := &hookAudit{onWrite: func(e Event) error {
		if e.Type == EventSnapshot {
			time.Sleep(20 * time.Millisecond)
		}
		return nil
	}}
	cfg := testConfig(fc, au, &recordAlert{}, store)
	cfg.ControlledGate = allowGate
	cfg.MaxRunDuration = 2 * time.Millisecond
	res := NewEngine(cfg).Run(context.Background(), req)
	if res.State != StateCancelled {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCancelled)
	}
	out := outcomeOf(t, au.events)
	if !strings.Contains(out.Fields["stop"], ErrRunTimeLimit.Error()) {
		t.Errorf("outcome stop = %q, want the time limit", out.Fields["stop"])
	}
}

// A run completed normally records the rollback as verified and no stop reason.
func TestLifecycleAudit_CleanRunHasNoStopReason(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	au := &hookAudit{}
	cfg := testConfig(fc, au, &recordAlert{}, store)
	cfg.ControlledGate = allowGate
	res := NewEngine(cfg).Run(context.Background(), req)
	if res.State != StateCleaned {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCleaned)
	}
	out := outcomeOf(t, au.events)
	if out.Fields["rollback"] != "verified" || out.Fields["stop"] != "" {
		t.Errorf("rollback=%q stop=%q, want verified and no stop", out.Fields["rollback"], out.Fields["stop"])
	}
}

// A gate denial before the run is refused and audited with the reason, and writes nothing to the cluster.
func TestLifecycleAudit_GateRefusalIsAuditedWithItsReason(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	au := &hookAudit{}
	cfg := testConfig(fc, au, &recordAlert{}, store)
	cfg.ControlledGate = func(context.Context, RunRequest) error { return ErrControlledDisabled }
	res := NewEngine(cfg).Run(context.Background(), req)
	if res.State != StateRefused {
		t.Fatalf("state = %s, want %s", res.State, StateRefused)
	}
	var refused *Event
	for i := range au.events {
		if au.events[i].Type == EventRefused {
			refused = &au.events[i]
		}
	}
	if refused == nil || !strings.Contains(refused.Fields["reason"], "controlled gate") {
		t.Fatalf("gate refusal must be audited with its reason; events = %v", eventTypes(au.events))
	}
}
