package runstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/segprobe/runstore"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

func withStore(t *testing.T, fn func(ctx context.Context, s *runstore.Store)) {
	t.Helper()
	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureSegmentationSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		fn(ctx, runstore.New(pool))
	})
}

func TestStore_RoundTripKeepsVerdictsAndOrder(t *testing.T) {
	withStore(t, func(ctx context.Context, s *runstore.Store) {
		run, err := s.Create(ctx, "swift-isolation", "admin@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetRunning(ctx, run.ID); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		rows := []runstore.ProbeRow{
			{ProbeID: "corp-to-swift", Src: "corp", Dst: "swift", DstPort: 8443, Proto: "tcp", Expect: "deny", Outcome: "timeout", Verdict: "PASS", Reason: "blocked", RuleIDs: []string{"SEG-DENY-SWIFT-1"}, StartedAt: &now, EndedAt: &now},
			{ProbeID: "swift-local-control", Src: "swift", Dst: "swift", DstPort: 8443, Proto: "tcp", Expect: "allow", Outcome: "connected", Verdict: "PASS", Reason: "same-zone", StartedAt: &now, EndedAt: &now},
		}
		if err := s.SaveRunResults(ctx, run.ID, 0, rows); err != nil {
			t.Fatal(err)
		}
		stable := true
		if err := s.Finish(ctx, run.ID, "completed", 1, &stable, ""); err != nil {
			t.Fatal(err)
		}

		got, probes, err := s.Get(ctx, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "completed" || got.Runs != 1 || got.Stable == nil || !*got.Stable {
			t.Fatalf("run = %+v", got)
		}
		if len(probes) != 2 || probes[0].ProbeID != "corp-to-swift" || probes[1].ProbeID != "swift-local-control" {
			t.Fatalf("probes out of order: %+v", probes)
		}
		if probes[0].Verdict != "PASS" || len(probes[0].RuleIDs) != 1 || probes[0].RuleIDs[0] != "SEG-DENY-SWIFT-1" {
			t.Fatalf("verdict or rule not kept verbatim: %+v", probes[0])
		}
	})
}

func TestStore_GetUnknownRunIsNotFound(t *testing.T) {
	withStore(t, func(ctx context.Context, s *runstore.Store) {
		if _, _, err := s.Get(ctx, "00000000-0000-0000-0000-000000000000"); err != runstore.ErrNotFound {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})
}

func TestStore_FailStaleClearsInterruptedRuns(t *testing.T) {
	withStore(t, func(ctx context.Context, s *runstore.Store) {
		run, err := s.Create(ctx, "core-banking-tiering", "admin@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetRunning(ctx, run.ID); err != nil {
			t.Fatal(err)
		}
		n, err := s.FailStale(ctx, "interrupted by restart")
		if err != nil || n != 1 {
			t.Fatalf("FailStale = %d, %v; want 1", n, err)
		}
		got, _, err := s.Get(ctx, run.ID)
		if err != nil || got.Status != "failed" || got.FailureReason != "interrupted by restart" {
			t.Fatalf("run = %+v, err %v", got, err)
		}
	})
}
