package testutil

import (
	"testing"
	"time"
)

func TestFrozenClock_AdvanceMovesTime(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := NewFrozenClock(start)

	if !clock.Now().Equal(start) {
		t.Fatalf("Now() = %v, want %v", clock.Now(), start)
	}

	clock.Advance(24 * time.Hour)
	want := start.Add(24 * time.Hour)
	if !clock.Now().Equal(want) {
		t.Fatalf("after Advance, Now() = %v, want %v", clock.Now(), want)
	}
}

func TestSeqUUID_Deterministic(t *testing.T) {
	g := NewSeqUUID("test", 0)
	first := g.Next()
	second := g.Next()
	if first == second {
		t.Fatal("expected distinct sequential ids")
	}

	g2 := NewSeqUUID("test", 0)
	got := g2.Next()
	if got != first {
		t.Fatalf("same seed should reproduce same first id: got %q, want %q", got, first)
	}
}

func TestSeededRand_SameSeedSameSequence(t *testing.T) {
	r1 := SeededRand(42)
	r2 := SeededRand(42)

	for i := 0; i < 5; i++ {
		v1 := r1.Int63()
		v2 := r2.Int63()
		if v1 != v2 {
			t.Fatalf("iteration %d: r1=%d r2=%d, want equal", i, v1, v2)
		}
	}
}
