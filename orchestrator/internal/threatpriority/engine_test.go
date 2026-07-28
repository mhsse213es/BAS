package threatpriority

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestNewEngine_UsesDefaultFactors(t *testing.T) {
	e := NewEngine(nil, scenario.NewEngine(t.TempDir()), nil, nil)
	if len(e.factors) != 9 {
		t.Fatalf("got %d factors, want 9", len(e.factors))
	}
}

func TestScoreActor_ComputesCompositeFromRealFactors(t *testing.T) {
	// Exercises scoreActor directly with a hand-built sharedIndexes, bypassing
	// the DB (e.pool is nil, and previousScore is nil-pool-safe -- see
	// engine.go). Full ScoreAll/Score DB-backed behavior is covered by
	// history_test.go in Task 8, once threat_priority_history exists.
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{"T1059": true},
		detection:  map[string]bool{"T1059": true},
		purple:     map[string]bool{},
		compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-ACTOR-X", Confidence: "high"}

	// Name won't resolve against attackdata.GroupTechniqueIndex, so
	// scoreActor's own technique resolution yields nil TechniqueIDs --
	// exercise the "no known techniques" path deliberately here, and cover
	// the real-technique path via ScoreAll's DB-backed integration test in
	// Task 8/10 instead (technique resolution depends on real embedded
	// ATT&CK data, not something to fake in a unit test).
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap.Tier == "" {
		t.Fatal("expected a non-empty tier")
	}
	if len(ap.Factors) != 9 {
		t.Fatalf("got %d factor results, want 9", len(ap.Factors))
	}
}
