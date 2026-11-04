package k8sscenario

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// allowGate is the Controlled gate for tests that expect the run to proceed.
func allowGate(context.Context, RunRequest) error { return nil }

// Cancelling in the window after the snapshot is recorded and before the first write stops the run before it writes.
// The prior value is restored, verified, and the run is reported CANCELLED.
func TestLifecycle_CancelBeforeFirstWriteWritesNothingAndRestores(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
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
	if !strings.Contains(res.Error, ErrCancelledByOperator.Error()) {
		t.Errorf("the outcome must say why the run stopped; got %q", res.Error)
	}
	if got := fc.objects[cmKey].Data["state"]; got != "original" {
		t.Fatalf("value = %q, want the prior value restored", got)
	}
}

// Cancelling during the write: the write completes, rollback restores the prior value on a context the stop cannot
// cancel, and only then is the run reported CANCELLED.
func TestLifecycle_CancelDuringApplyIsRolledBackAndVerified(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	var eng *Engine
	calls := 0
	fc.onSetData = func() {
		calls++
		if calls == 1 {
			eng.Cancel(req.RunID)
		}
	}
	cfg := testConfig(fc, &hookAudit{}, &recordAlert{}, store)
	cfg.ControlledGate = allowGate
	eng = NewEngine(cfg)
	res := eng.Run(context.Background(), req)
	if res.State != StateCancelled {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCancelled)
	}
	if calls < 2 {
		t.Fatalf("rollback did not run after the stop (writes: %d)", calls)
	}
	if got := fc.objects[cmKey].Data["state"]; got != "original" {
		t.Fatalf("value = %q, want the prior value restored", got)
	}
}

// A stop whose rollback cannot be verified ends in CLEANUP_FAILED and raises an alert. It is never reported as
// cancelled and cleaned.
func TestLifecycle_CancelWithFailedRollbackIsCleanupFailed(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	var eng *Engine
	fc.onSetData = func() {
		eng.Cancel(req.RunID)
		fc.failSetData = true
	}
	alert := &recordAlert{}
	cfg := testConfig(fc, &hookAudit{}, alert, store)
	cfg.ControlledGate = allowGate
	eng = NewEngine(cfg)
	res := eng.Run(context.Background(), req)
	if res.State != StateCleanupFailed {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCleanupFailed)
	}
	if !strings.Contains(res.Error, "stopped:") {
		t.Errorf("the stop must be recorded with the failure; got %q", res.Error)
	}
	if len(alert.msgs) == 0 || !strings.Contains(alert.msgs[0], "CLEANUP_FAILED") {
		t.Fatalf("CLEANUP_FAILED must alert; alerts = %v", alert.msgs)
	}
}

// A gate that denies at planning or at the start of the run writes nothing.
func TestLifecycle_GateDenialBeforeTheRunWritesNothing(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	cfg := testConfig(fc, &hookAudit{}, &recordAlert{}, store)
	cfg.ControlledGate = func(context.Context, RunRequest) error { return ErrControlledDisabled }
	res := NewEngine(cfg).Run(context.Background(), req)
	if res.State != StateRefused {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateRefused)
	}
	if len(fc.writes) != 0 {
		t.Fatalf("a refused run must write nothing; writes = %v", fc.writes)
	}
	if got := fc.objects[cmKey].Data["state"]; got != "original" {
		t.Fatalf("value = %q, want original", got)
	}
}

// The kill switch is turned off after the run started. The gate is checked again immediately before the first write:
// nothing is written, and the run does not report cleanup it did not perform.
func TestLifecycle_KillSwitchOffBeforeFirstWriteStopsTheRun(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	calls := 0
	cfg := testConfig(fc, &hookAudit{}, &recordAlert{}, store)
	cfg.ControlledGate = func(context.Context, RunRequest) error {
		calls++
		if calls == 1 {
			return nil
		}
		return ErrControlledDisabled
	}
	res := NewEngine(cfg).Run(context.Background(), req)
	if res.State == StateCleanupFailed || res.State == StateCleaned {
		t.Fatalf("state = %s (%s); a run stopped before its first write must not claim a change", res.State, res.Error)
	}
	if !strings.Contains(res.Error, ErrControlledDisabled.Error()) {
		t.Fatalf("error = %q, want the kill switch reason", res.Error)
	}
	if got := fc.objects[cmKey].Data["state"]; got != "original" {
		t.Fatalf("value = %q, want original; the kill switch must stop the write", got)
	}
}

// The 10-minute limit stops the run: here the limit is already past, so nothing is written and the run is CANCELLED
// with the time-limit reason.
func TestLifecycle_TimeLimitStopsTheRun(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	// The snapshot write waits past the limit, so the deadline has certainly passed before the first write.
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
	if !strings.Contains(res.Error, ErrRunTimeLimit.Error()) {
		t.Fatalf("error = %q, want the time-limit reason", res.Error)
	}
	if got := fc.objects[cmKey].Data["state"]; got != "original" {
		t.Fatalf("value = %q, want original", got)
	}
}

// Stopping a run that is not executing reports false and changes nothing.
func TestLifecycle_CancelOfAnIdleRunReportsFalse(t *testing.T) {
	cfg := testConfig(newFakeClient(), &hookAudit{}, &recordAlert{}, newMemApprovals())
	eng := NewEngine(cfg)
	if eng.Cancel("no-such-run") {
		t.Fatal("Cancel of an idle run must report false")
	}
	if n := eng.CancelControlled(); n != 0 {
		t.Fatalf("CancelControlled stopped %d runs with none executing", n)
	}
}

// The gate denies unless the switch is on, the cluster has an active authorization for this exact action and
// namespace, and that record is the one the run was planned under.
func TestControlledGate(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC) }
	active := CustomerAuthorization{ID: "k8sa-1", ClusterID: testClusterID, CustomerRef: "cust-1",
		Scenarios: []string{"configmap-patch-labelled"}, Namespaces: []string{testNS},
		AuthorizedAt: now().Add(-time.Hour), ExpiresAt: now().Add(time.Hour)}
	revoked := active
	at := now()
	revoked.RevokedAt = &at

	base := RunRequest{ClusterID: testClusterID, AuthorizationID: "k8sa-1", CustomerRef: "cust-1",
		Namespace: testNS, ActionID: "configmap-patch-labelled"}
	cases := []struct {
		name    string
		on      bool
		readErr error
		recs    []CustomerAuthorization
		req     func(RunRequest) RunRequest
		want    error
	}{
		{name: "switch off", on: false, recs: []CustomerAuthorization{active}, want: ErrControlledDisabled},
		{name: "switch unreadable", readErr: errors.New("db down"), recs: []CustomerAuthorization{active}, want: errAny},
		{name: "no authorization", on: true, recs: nil, want: ErrAuthorizationDenied},
		{name: "authorization revoked", on: true, recs: []CustomerAuthorization{revoked}, want: ErrAuthorizationDenied},
		{name: "authorization replaced", on: true, recs: []CustomerAuthorization{active},
			req: func(r RunRequest) RunRequest { r.AuthorizationID = "k8sa-old"; return r }, want: ErrAuthorizationChanged},
		{name: "customer changed", on: true, recs: []CustomerAuthorization{active},
			req: func(r RunRequest) RunRequest { r.CustomerRef = "cust-2"; return r }, want: ErrAuthorizationChanged},
		{name: "no cluster id", on: true, recs: []CustomerAuthorization{active},
			req: func(r RunRequest) RunRequest { r.ClusterID = ""; return r }, want: ErrAuthorizationDenied},
		{name: "matching", on: true, recs: []CustomerAuthorization{active}, want: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gate := NewControlledGate(
				func(context.Context) (bool, error) { return c.on, c.readErr },
				func(context.Context, string) ([]CustomerAuthorization, error) { return c.recs, nil },
				now)
			r := base
			if c.req != nil {
				r = c.req(r)
			}
			err := gate(context.Background(), r)
			switch {
			case c.want == errAny:
				if err == nil {
					t.Fatal("want an error")
				}
			case c.want == nil:
				if err != nil {
					t.Fatalf("want allowed, got %v", err)
				}
			default:
				if !errors.Is(err, c.want) {
					t.Fatalf("got %v, want %v", err, c.want)
				}
			}
		})
	}
}

// errAny stands for "any error" in the gate table.
var errAny = errors.New("any")

// The approval audit records who approved, for which customer, cluster, authorization, scenario and namespace, the
// exact parameters, and the approval's time and expiry.
func TestApprovalEvent_RecordsTheBinding(t *testing.T) {
	a := Approval{ID: "appr-1", ApproverID: "op-2", RequesterID: "op-1", RunID: "run-1", ClusterID: testClusterID,
		AuthorizationID: "k8sa-1", CustomerRef: "cust-1", Cluster: testCluster, Namespace: testNS,
		ActionID: "configmap-patch-labelled", ParamsHash: "h",
		ApprovedAt: time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 10, 23, 10, 15, 0, 0, time.UTC)}
	ev := ApprovalEvent(a, map[string]string{"name": "bas-fixture", "value": "x"})
	if ev.Type != EventApproved {
		t.Fatalf("type = %s", ev.Type)
	}
	want := map[string]string{"approver": "op-2", "requester": "op-1", "clusterId": testClusterID,
		"authorizationId": "k8sa-1", "customerRef": "cust-1", "namespace": testNS, "action": "configmap-patch-labelled",
		"approvedAt": "2026-10-23T10:00:00Z", "expiresAt": "2026-10-23T10:15:00Z"}
	for k, v := range want {
		if ev.Fields[k] != v {
			t.Errorf("%s = %q, want %q", k, ev.Fields[k], v)
		}
	}
	if !strings.Contains(ev.Fields["params"], `"value":"x"`) {
		t.Errorf("the exact parameters must be recorded; got %q", ev.Fields["params"])
	}
}
