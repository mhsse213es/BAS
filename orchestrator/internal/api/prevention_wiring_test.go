package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/rwprevent"
)

type noBlocks struct{}

func (noBlocks) FindBlocks(context.Context, string, time.Time, time.Time) ([]rwprevent.Block, error) {
	return nil, nil
}

// With no block source configured, Prevention must stay the canned fake, which
// returns an unknown observation (skipped). Wiring a source must switch to the
// real observer and never leave the fake in place.
func TestPreventionObserverFor_NoSourceUsesUnknownFake(t *testing.T) {
	h := &Handler{}
	obs, err := h.preventionObserverFor(models.SimulationResult{}).ObservePrevention(
		context.Background(), rwevidence.AttemptKey{RunID: "r", TechniqueID: "T1486", Action: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Outcome != controlval.OutcomeUnknown {
		t.Fatalf("unconfigured prevention outcome = %q, want unknown", obs.Outcome)
	}
}

func TestPreventionObserverFor_ConfiguredSourceSelectsRealObserver(t *testing.T) {
	h := (&Handler{}).WithPreventionBlocks(noBlocks{})
	if _, ok := h.preventionObserverFor(models.SimulationResult{}).(rwprevent.Observer); !ok {
		t.Fatal("configured block source must select rwprevent.Observer")
	}
}
