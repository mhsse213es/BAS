package threatpriority

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

func TestSnapshotHistoryAndPreviousScore_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, confidence)
			 VALUES ($1, '{}', '{}', '{}', 'high') ON CONFLICT (name) DO NOTHING`,
			"HISTORY-TEST-ACTOR")
		if err != nil {
			t.Fatalf("seed profile: %v", err)
		}

		e := NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)

		if err := e.SnapshotHistory(ctx); err != nil {
			t.Fatalf("first SnapshotHistory: %v", err)
		}
		_, hasPrev, err := e.previousScore(ctx, "HISTORY-TEST-ACTOR")
		if err != nil {
			t.Fatalf("previousScore after first snapshot: %v", err)
		}
		if !hasPrev {
			t.Fatal("expected a history row after SnapshotHistory")
		}

		hist, err := e.History(ctx, "HISTORY-TEST-ACTOR", 10)
		if err != nil {
			t.Fatalf("History: %v", err)
		}
		if len(hist) == 0 {
			t.Fatal("expected at least one history row")
		}
	})
}

func TestPreviousScore_NoHistory_ReturnsFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)
		_, hasPrev, err := e.previousScore(context.Background(), "NO-SUCH-ACTOR-EVER")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasPrev {
			t.Fatal("expected hasPrev=false for an actor with no history")
		}
	})
}
