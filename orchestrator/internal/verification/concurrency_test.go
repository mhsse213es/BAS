package verification

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// raceAttest fires n concurrent Attest calls for one (runID, expectationID)
// pair and asserts the store's actual concurrency invariants:
//
//  1. at least one call succeeds;
//  2. every failure is ErrConflict — never a raw SQL error or corrupt state;
//  3. afterwards exactly ONE active row exists for the pair;
//  4. the history row count equals the success count (each success appended
//     exactly one row to the supersede chain, no lost or duplicated writes).
//
// Note "exactly one success" is deliberately NOT asserted: a goroutine whose
// transaction starts after an earlier winner commits sees that winner's
// active row and legitimately supersedes it — that is sequential operation,
// not a race loss. Only genuinely overlapping transactions conflict.
func raceAttest(t *testing.T, store *Store, runID, expectationID string, n, priorRows int) {
	t.Helper()
	ctx := context.Background()

	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Attest(ctx, AttestInput{
				RunID: runID, ExpectationID: expectationID, VerifiedBy: "racer",
			})
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var succeeded, conflicts int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error (want nil or ErrConflict): %v", err)
		}
	}
	if succeeded < 1 {
		t.Fatalf("succeeded = %d, want at least 1", succeeded)
	}
	if succeeded+conflicts != n {
		t.Fatalf("succeeded(%d) + conflicts(%d) != n(%d)", succeeded, conflicts, n)
	}

	current, err := store.CurrentForRun(ctx, runID)
	if err != nil {
		t.Fatalf("CurrentForRun: %v", err)
	}
	if len(current) != 1 {
		t.Fatalf("CurrentForRun returned %d active records, want exactly 1", len(current))
	}

	history, err := store.History(ctx, runID, expectationID)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if want := succeeded + priorRows; len(history) != want {
		t.Fatalf("History has %d rows, want %d (successes + prior rows — no lost or duplicated writes)", len(history), want)
	}
	var activeCount int
	for _, rec := range history {
		if rec.Active {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("history contains %d active rows, want exactly 1", activeCount)
	}
}

func TestAttest_ConcurrentRace_NoPriorRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		raceAttest(t, store, "race-run", "race-exp", 5, 0)
	})
}

func TestAttest_ConcurrentRace_WithPriorRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		if _, err := store.Attest(context.Background(), AttestInput{
			RunID: "race-run-2", ExpectationID: "race-exp-2", VerifiedBy: "seed",
		}); err != nil {
			t.Fatalf("seed Attest: %v", err)
		}
		raceAttest(t, store, "race-run-2", "race-exp-2", 5, 1)
	})
}
