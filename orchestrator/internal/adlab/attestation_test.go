package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/scenario"
)

func TestSyntheticLabsAreStampedAndFlowThroughGate(t *testing.T) {
	labs, err := SyntheticProvider{}.Labs()
	if err != nil {
		t.Fatalf("synthetic provider must not error: %v", err)
	}
	for _, l := range labs {
		d := adgate.Decide(adgate.Request{
			Class: scenario.ClassNonDestructive,
			Env:   l.Attestation,
			Auth:  adgate.Authorization{Authorized: true},
		})
		if !d.Allowed || d.Reason != adgate.ReasonAllowedSyntheticAuthorized {
			t.Errorf("lab %q: stamped synthetic attestation must allow through the gate, got %+v", l.Name, d)
		}
	}
}

func TestUnstampedLabDeniesThroughGate(t *testing.T) {
	// A hand-built Lab with no stamp carries zero-value provenance -> deny.
	l := Lab{Name: "unstamped"}
	d := adgate.Decide(adgate.Request{
		Class: scenario.ClassNonDestructive,
		Env:   l.Attestation,
		Auth:  adgate.Authorization{Authorized: true},
	})
	if d.Allowed || d.Reason != adgate.ReasonDeniedNotSynthetic {
		t.Fatalf("unstamped lab must deny not_synthetic, got %+v", d)
	}
}
