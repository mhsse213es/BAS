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
