package controlval

import (
	"context"
	"errors"
	"testing"
)

func TestFakeProvider_ReturnsCannedObservationWithKey(t *testing.T) {
	f := &FakeProvider{
		ProviderName: "fake",
		Obs: map[string]Observation{
			"dcsync": {Outcome: OutcomeBlocked, EvidenceKind: EvidenceObserved, Confidence: ConfidenceHigh, Source: "fake-api"},
		},
	}
	key := CorrelationKey{RunID: "r1", Target: "dc01", Action: "dcsync"}
	got, err := f.Observe(context.Background(), key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Outcome != OutcomeBlocked {
		t.Fatalf("outcome = %q, want blocked", got.Outcome)
	}
	if got.Key != key {
		t.Fatalf("Observe must stamp the requested key; got %+v want %+v", got.Key, key)
	}
	if got.Provider != "fake" {
		t.Fatalf("provider = %q, want fake", got.Provider)
	}
}

func TestFakeProvider_UnknownActionReturnsUnknownNotError(t *testing.T) {
	// A canned observation for a DIFFERENT action must never be reused, and no
	// outcome/confidence/evidence must be manufactured for the uncaptured one.
	f := &FakeProvider{
		ProviderName: "fake",
		Obs: map[string]Observation{
			"dcsync": {Outcome: OutcomeBlocked, EvidenceKind: EvidenceObserved, Confidence: ConfidenceHigh, Source: "fake-api"},
		},
	}
	got, err := f.Observe(context.Background(), CorrelationKey{Action: "never-seen"})
	if err != nil {
		t.Fatalf("missing correlation must NOT be an error: %v", err)
	}
	if got.Outcome != OutcomeUnknown {
		t.Fatalf("outcome = %q, want unknown (no reuse of another action's canned obs)", got.Outcome)
	}
	if got.EvidenceKind != "" {
		t.Fatalf("evidenceKind = %q, want empty (none fabricated)", got.EvidenceKind)
	}
	if got.Confidence != ConfidenceNone {
		t.Fatalf("confidence = %q, want none (none fabricated)", got.Confidence)
	}
	if got.Source == "fake-api" {
		t.Fatal("must not inherit another action's Source")
	}
}

func TestFakeProvider_ConfiguredErrorIsErrorNotUnknown(t *testing.T) {
	f := &FakeProvider{ProviderName: "fake", Err: map[string]error{"boom": errors.New("api down")}}
	got, err := f.Observe(context.Background(), CorrelationKey{Action: "boom"})
	if err == nil {
		t.Fatal("expected a technical error for the configured action")
	}
	if got.Outcome == OutcomeUnknown {
		t.Fatal("a technical failure must NOT be represented as an Unknown observation")
	}
	if got.Outcome != "" {
		t.Fatalf("error path must return a zero observation, got outcome %q", got.Outcome)
	}
}

func TestFakeProvider_SatisfiesProviderInterface(t *testing.T) {
	var _ Provider = (*FakeProvider)(nil)
}
