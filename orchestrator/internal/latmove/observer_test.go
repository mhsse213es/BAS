package latmove

import (
	"context"
	"errors"
	"testing"
)

func lookupKey(k AttemptKey) string { return k.RunID + "/" + k.Technique }

func TestFakeObserver_ReturnsCannedObservationWithKey(t *testing.T) {
	k := AttemptKey{RunID: "r1", Source: "ws01", Destination: "ws02", Technique: "wmi-remote-process-creation"}
	f := &FakeObserver{Obs: map[string]Observation{
		lookupKey(k): {Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}},
	}}
	got, err := f.Observe(context.Background(), k)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Key != k {
		t.Fatalf("Observe must stamp the requested key; got %+v want %+v", got.Key, k)
	}
	if ClassifyAttempt(got) != ResultExecuted {
		t.Fatalf("expected Executed, got %+v", got)
	}
}

func TestFakeObserver_UncapturedKeyFabricatesNothing(t *testing.T) {
	k1 := AttemptKey{RunID: "r1", Technique: "wmi-remote-process-creation"}
	k2 := AttemptKey{RunID: "r2", Technique: "wmi-remote-process-creation"}
	f := &FakeObserver{Obs: map[string]Observation{
		lookupKey(k1): {Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}},
	}}
	got, err := f.Observe(context.Background(), k2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Marker.Found {
		t.Fatal("must not reuse another key's canned marker")
	}
	if got.Marker.Correlated {
		t.Fatal("an uncaptured key must not claim correlation")
	}
	if got.Call != CallUnknown {
		t.Fatalf("call = %q, want unknown for an uncaptured key", got.Call)
	}
	if ClassifyAttempt(got) != ResultIndeterminate {
		t.Fatal("an uncaptured key must classify as Indeterminate, never Executed or AccessDenied")
	}
}

func TestFakeObserver_ConfiguredErrorPropagates(t *testing.T) {
	k := AttemptKey{RunID: "boom", Technique: "wmi-remote-process-creation"}
	f := &FakeObserver{Err: map[string]error{lookupKey(k): errors.New("winrm down")}}
	if _, err := f.Observe(context.Background(), k); err == nil {
		t.Fatal("expected the configured error to propagate")
	}
}

func TestFakeObserver_SatisfiesExecutionObserver(t *testing.T) {
	var _ ExecutionObserver = (*FakeObserver)(nil)
}
