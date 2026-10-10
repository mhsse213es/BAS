package adefficacy

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func observe(t *testing.T, d ControlDecision, err error) (controlval.Observation, error) {
	t.Helper()
	p := &NativeADProvider{Src: fakeSource{dec: d, err: err}}
	return p.Observe(context.Background(), controlval.CorrelationKey{RunID: "r1", Target: "dc01", Action: "dcsync"})
}

func TestObserve_AccessDeniedIsBlockedObservedHigh(t *testing.T) {
	got, err := observe(t, ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Corroborated, Correlated: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != controlval.OutcomeBlocked || got.EvidenceKind != controlval.EvidenceObserved || got.Confidence != controlval.ConfidenceHigh {
		t.Fatalf("got %+v, want blocked/observed/high", got)
	}
	if got.Provider != "native-ad" {
		t.Fatalf("provider = %q", got.Provider)
	}
}

func TestObserve_SucceededIsAllowedHigh(t *testing.T) {
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPISucceeded, Audit4662: Corroborated, Correlated: true}, nil)
	if got.Outcome != controlval.OutcomeAllowed || got.Confidence != controlval.ConfidenceHigh {
		t.Fatalf("got %+v, want allowed/high", got)
	}
}

func TestObserve_ConclusiveWithoutCorroborationStaysHigh(t *testing.T) {
	// DRSUAPI is the authoritative primary; a missing 4662 must NOT lower it.
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Uncorroborated, Correlated: true}, nil)
	if got.Outcome != controlval.OutcomeBlocked || got.Confidence != controlval.ConfidenceHigh {
		t.Fatalf("got %+v, want blocked/high (DRSUAPI primary, 4662 optional)", got)
	}
}

func TestObserve_Event4662AloneDoesNotEstablishBlocked(t *testing.T) {
	// Indeterminate DRSUAPI + present 4662 must stay Unknown, never Blocked.
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPIIndeterminate, Audit4662: Corroborated, Correlated: true}, nil)
	if got.Outcome != controlval.OutcomeUnknown {
		t.Fatalf("outcome = %q, want unknown (4662 alone never establishes blocked)", got.Outcome)
	}
}

func TestObserve_UncorrelatedIsNoneConfidence(t *testing.T) {
	got, _ := observe(t, ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Corroborated, Correlated: false}, nil)
	if got.Confidence != controlval.ConfidenceNone {
		t.Fatalf("confidence = %q, want none (uncorrelated)", got.Confidence)
	}
}

func TestObserve_SourceErrorPropagates(t *testing.T) {
	if _, err := observe(t, ControlDecision{}, errors.New("winrm down")); err == nil {
		t.Fatal("expected source error to propagate (-> ERROR via Evaluate)")
	}
}

func TestNativeADProvider_SatisfiesProvider(t *testing.T) {
	var _ controlval.Provider = (*NativeADProvider)(nil)
}
