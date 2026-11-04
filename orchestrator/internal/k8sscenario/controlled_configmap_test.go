package k8sscenario

import (
	"context"
	"errors"
	"testing"
	"time"
)

// enableControlledForTest marks one action Controlled for the duration of a test only. Production classification
// stays empty; the engine behaviour under test is the same as it would be once the action is enabled.
func enableControlledForTest(t *testing.T, id string) {
	t.Helper()
	prev := controlledActions
	controlledActions = map[string]bool{id: true}
	t.Cleanup(func() { controlledActions = prev })
}

// controlledCM sets up a sandbox ConfigMap holding "original" and a valid approval for a live patch to value.
func controlledCM(t *testing.T, value string) (*fakeClient, *memApprovals, RunRequest) {
	t.Helper()
	fc := newFakeClient()
	fc.objects["ConfigMap/bas-sandbox/bas-fixture"] = Object{
		Ref:    ObjectRef{Kind: "ConfigMap", Namespace: testNS, Name: "bas-fixture"},
		Labels: map[string]string{FixtureLabel: "true"},
		Data:   map[string]string{"state": "original"},
	}
	store := newMemApprovals()
	req := RunRequest{ClusterID: testClusterID, RunID: "run-cm", Requester: "operator-1", Cluster: ClusterRef{Name: testCluster, Server: testServer},
		Namespace: testNS, ActionID: "configmap-patch-labelled", Params: map[string]string{"name": "bas-fixture", "value": value}, Live: true}
	a := Approval{ClusterID: testClusterID, ID: "appr-cm", ApproverID: "operator-2", RequesterID: req.Requester, RunID: req.RunID, Cluster: testCluster,
		Namespace: testNS, ActionID: req.ActionID, ParamsHash: HashParams(req.Params), ExpiresAt: time.Date(2026, 10, 23, 10, 30, 0, 0, time.UTC)}
	if err := store.Put(a); err != nil {
		t.Fatal(err)
	}
	req.ApprovalID = a.ID
	return fc, store, req
}

// hookAudit runs onWrite before it records an event, so a test can see the cluster state at that moment.
type hookAudit struct {
	events  []Event
	onWrite func(Event) error
}

func (a *hookAudit) Write(_ context.Context, e Event) error {
	if a.onWrite != nil {
		if err := a.onWrite(e); err != nil {
			return err
		}
	}
	a.events = append(a.events, e)
	return nil
}

const cmKey = "ConfigMap/bas-sandbox/bas-fixture"

// The prior state is recorded before the first write, and the record names the approval and the prior value.
func TestControlledConfigMap_SnapshotIsRecordedBeforeTheFirstWrite(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	var valueAtSnapshot string
	au := &hookAudit{onWrite: func(e Event) error {
		if e.Type == EventSnapshot {
			valueAtSnapshot = fc.objects[cmKey].Data["state"]
		}
		return nil
	}}
	res := NewEngine(testConfig(fc, au, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateCleaned {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCleaned)
	}
	if valueAtSnapshot != "original" {
		t.Fatalf("the snapshot must be recorded before any change; the value at that point was %q", valueAtSnapshot)
	}
	var snap *Event
	for i := range au.events {
		if au.events[i].Type == EventSnapshot {
			snap = &au.events[i]
		}
	}
	if snap == nil {
		t.Fatal("a Controlled run must record a snapshot event")
	}
	if snap.Fields["priorValue"] != "original" || snap.Fields["priorPresent"] != "true" || snap.Fields["approvalId"] != req.ApprovalID {
		t.Errorf("snapshot record incomplete or unbound to the approval: %+v", snap.Fields)
	}
}

// If the snapshot cannot be recorded, nothing is applied: the run is refused and the ConfigMap is unchanged.
func TestControlledConfigMap_UnrecordedSnapshotMeansNothingIsApplied(t *testing.T) {
	enableControlledForTest(t, "configmap-patch-labelled")
	fc, store, req := controlledCM(t, "changed")
	au := &hookAudit{onWrite: func(e Event) error {
		if e.Type == EventSnapshot {
			return errors.New("audit store down")
		}
		return nil
	}}
	res := NewEngine(testConfig(fc, au, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateRefused {
		t.Fatalf("state = %s, want %s when the snapshot cannot be recorded", res.State, StateRefused)
	}
	if got := fc.objects[cmKey].Data["state"]; got != "original" {
		t.Fatalf("nothing may be changed when the snapshot is not recorded; the value is %q", got)
	}
}

// A non-Controlled action does not write a snapshot event; its behaviour is unchanged.
func TestLabOnlyAction_WritesNoSnapshotEvent(t *testing.T) {
	fc := newFakeClient()
	store := newMemApprovals()
	req := podRequest(true, "")
	a := approvedPod(t, store, req)
	req.ApprovalID = a
	au := &hookAudit{}
	NewEngine(testConfig(fc, au, &recordAlert{}, store)).Run(context.Background(), req)
	for _, e := range au.events {
		if e.Type == EventSnapshot {
			t.Fatalf("a lab-only action must not write a snapshot event: %+v", e)
		}
	}
}
