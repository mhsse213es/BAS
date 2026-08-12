package threatpriority

import (
	"context"
	"testing"
	"time"
)

func TestIntelFreshnessFactor_Recent(t *testing.T) {
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	seen := now.Add(-10 * 24 * time.Hour)
	f := IntelFreshnessFactor{}
	raw, _, available, err := f.Score(context.Background(), Context{Now: now, Profile: &ActorProfile{LastSeen: &seen}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

func TestIntelFreshnessFactor_NoLastSeen_Unavailable(t *testing.T) {
	f := IntelFreshnessFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{Profile: &ActorProfile{}})
	if available {
		t.Fatal("expected available=false with no LastSeen")
	}
}

func TestRelevanceFactor_SectorMatch(t *testing.T) {
	f := RelevanceFactor{}
	raw, _, available, _ := f.Score(context.Background(), Context{
		Sectors: []string{"Financial Services"},
		Profile: &ActorProfile{Sectors: []string{"financial services"}},
	})
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

// TestRelevanceFactor_ActorHasNoSectorRegionData_Unavailable is the
// regression test for a real scoring bug: an actor profile with empty
// Sectors AND empty Regions (e.g. every OpenCTI-only actor -- OpenCTI's
// GraphQL query never fetches sector/region relationships at all, see
// opencti.go) was being scored as a CONFIRMED "no overlap" (raw=0,
// available=true), which the composite counts as real evidence against
// relevance. That's wrong: an empty profile here means "no source ever
// told us," not "we checked and it doesn't match." Unknown must stay
// unavailable, the same as the Profile==nil case just above it.
func TestRelevanceFactor_ActorHasNoSectorRegionData_Unavailable(t *testing.T) {
	f := RelevanceFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{
		Sectors: []string{"Financial Services"},
		Profile: &ActorProfile{}, // e.g. an OpenCTI-only actor -- Sectors/Regions never populated
	})
	if available {
		t.Fatal("expected available=false when the actor profile has no sector/region data at all -- unknown, not a confirmed non-match")
	}
}

// TestRelevanceFactor_ActorHasDataButNoOverlap locks in the other side of
// the same fix: an actor that DOES carry real sector/region data (e.g. a
// MISP-sourced actor with sector: tags) that simply doesn't match the
// org's configured sectors/regions is still a genuine, confirmed
// non-match -- available=true, raw=0 -- not "unknown".
func TestRelevanceFactor_ActorHasDataButNoOverlap(t *testing.T) {
	f := RelevanceFactor{}
	raw, _, available, _ := f.Score(context.Background(), Context{
		Sectors: []string{"Financial Services"},
		Profile: &ActorProfile{Sectors: []string{"Healthcare"}},
	})
	if !available || raw != 0 {
		t.Fatalf("raw=%.2f available=%v, want 0/true (actor has real sector data, just doesn't overlap -- a confirmed non-match)", raw, available)
	}
}

func TestRelevanceFactor_NoOrgConfig_Unavailable(t *testing.T) {
	f := RelevanceFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{Profile: &ActorProfile{Sectors: []string{"government"}}})
	if available {
		t.Fatal("expected available=false with no org sectors/regions configured")
	}
}

func TestConfidenceFactor_High(t *testing.T) {
	f := ConfidenceFactor{}
	raw, _, available, _ := f.Score(context.Background(), Context{Profile: &ActorProfile{Confidence: "high"}})
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

func TestConfidenceFactor_Empty_Unavailable(t *testing.T) {
	f := ConfidenceFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{Profile: &ActorProfile{}})
	if available {
		t.Fatal("expected available=false with empty confidence")
	}
}

func TestStandaloneFactors_FlatWeight(t *testing.T) {
	for _, f := range []ScoreFactor{IntelFreshnessFactor{}, RelevanceFactor{}, ConfidenceFactor{}} {
		if w := f.Weight(Context{ValidatedCount: 0}); w != flatWeight {
			t.Errorf("%s Weight = %.4f, want %.4f (flat, independent of ValidatedCount)", f.Name(), w, flatWeight)
		}
		if w := f.Weight(Context{ValidatedCount: 100}); w != flatWeight {
			t.Errorf("%s Weight = %.4f, want %.4f (flat, independent of ValidatedCount)", f.Name(), w, flatWeight)
		}
	}
}

func TestActivityFactor_Recent(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	last := now.Add(-3 * 24 * time.Hour)
	f := ActivityFactor{}
	raw, explanation, available, err := f.Score(context.Background(), Context{
		Now: now, Activity: &ActivitySignal{PulseCount: 4, LastObserved: &last},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
	if explanation == "" {
		t.Fatal("expected a non-empty explanation")
	}
}

func TestActivityFactor_Stale(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	last := now.Add(-20 * 24 * time.Hour)
	f := ActivityFactor{}
	raw, _, available, _ := f.Score(context.Background(), Context{
		Now: now, Activity: &ActivitySignal{PulseCount: 2, LastObserved: &last},
	})
	if !available || raw != 60 {
		t.Fatalf("raw=%.2f available=%v, want 60/true (8-29 day bucket)", raw, available)
	}
}

func TestActivityFactor_VeryStale(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	last := now.Add(-90 * 24 * time.Hour)
	f := ActivityFactor{}
	raw, _, available, _ := f.Score(context.Background(), Context{
		Now: now, Activity: &ActivitySignal{PulseCount: 1, LastObserved: &last},
	})
	if !available || raw != 20 {
		t.Fatalf("raw=%.2f available=%v, want 20/true (30+ day bucket)", raw, available)
	}
}

func TestActivityFactor_NoActivity_Unavailable(t *testing.T) {
	f := ActivityFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{Activity: nil})
	if available {
		t.Fatal("expected available=false with no Activity")
	}
}

func TestActivityFactor_WeightIsLowerThanCuratedStandaloneFactors(t *testing.T) {
	if (ActivityFactor{}).Weight(Context{}) >= (IntelFreshnessFactor{}).Weight(Context{}) {
		t.Fatal("ActivityFactor's weight must be lower than the curated standalone factors' -- activity evidence is a weaker signal than curated intelligence")
	}
}
