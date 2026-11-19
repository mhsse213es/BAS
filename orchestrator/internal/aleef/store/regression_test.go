package store_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/aleef/store"
)

func TestRegressionRoundTripAndNoOverwrite(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t-reg")
		bundle := []byte(`{"version":1,"x":"y"}`)
		if err := s.SaveRegression(ctx, f.ID, "ALEEF-REG-0001", bundle, []byte("id: a\n"), ""); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetRegression(ctx, f.ID)
		if err != nil || got.RegressionID != "ALEEF-REG-0001" || string(got.ScenarioYAML) != "id: a\n" || got.CreatedAt.IsZero() {
			t.Fatalf("got %+v err %v", got, err)
		}
		if !bytes.Contains(got.BundleJSON, []byte(`"version"`)) || !bytes.Contains(got.BundleJSON, []byte(`"x"`)) {
			t.Fatalf("bundle %s", got.BundleJSON)
		}
		err = s.SaveRegression(ctx, f.ID, "ALEEF-REG-0002", []byte(`{"version":2}`), nil, "note")
		if err == nil || !strings.Contains(err.Error(), "already saved") {
			t.Fatalf("second save: %v", err)
		}
		again, _ := s.GetRegression(ctx, f.ID)
		if again.RegressionID != "ALEEF-REG-0001" {
			t.Fatalf("overwritten: %+v", again)
		}
		// nil YAML round-trips as nil with its note
		_, f2 := newFinding(t, ctx, s, "t-reg2")
		if err := s.SaveRegression(ctx, f2.ID, "ALEEF-REG-0003", bundle, nil, "no scenario"); err != nil {
			t.Fatal(err)
		}
		g2, err := s.GetRegression(ctx, f2.ID)
		if err != nil || g2.ScenarioYAML != nil || g2.YAMLNote != "no scenario" {
			t.Fatalf("g2 %+v err %v", g2, err)
		}
		if _, err := s.GetRegression(ctx, "missing"); err == nil {
			t.Fatal("missing regression found")
		}
		if err := s.SaveRegression(ctx, "no-such-finding", "ALEEF-REG-0009", bundle, nil, ""); err == nil {
			t.Fatal("saved against a missing finding")
		}
	})
}

func TestNextRegressionSeqConcurrentDistinct(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		var mu sync.Mutex
		seen := map[int]bool{}
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := s.NextRegressionSeq(ctx)
				mu.Lock()
				defer mu.Unlock()
				if err != nil || n < 1 || n > 9999 || seen[n] {
					t.Errorf("seq %d err %v (duplicate or out of range)", n, err)
				}
				seen[n] = true
			}()
		}
		wg.Wait()
		if len(seen) != 20 {
			t.Fatalf("%d distinct values", len(seen))
		}
		a, _ := s.NextRegressionSeq(ctx)
		b, _ := s.NextRegressionSeq(ctx)
		if b <= a {
			t.Fatalf("not monotonic: %d then %d", a, b)
		}
	})
}

func TestNextRegressionSeqExhausted(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		if _, err := pool.Exec(ctx, `SELECT setval('aleef_regression_seq', 9999)`); err != nil {
			t.Fatal(err)
		}
		if n, err := s.NextRegressionSeq(ctx); err == nil {
			t.Fatalf("serial %d issued past 9999", n)
		}
		if _, err := pool.Exec(ctx, `SELECT setval('aleef_regression_seq', 1, false)`); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSetPriorKnowledge(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t-pk")
		before := historyCount(t, ctx, pool, f.ID)
		if err := s.SetPriorKnowledge(ctx, f.ID, "known_public", "carol"); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetFinding(ctx, f.ID)
		if got.PriorKnowledge != "known_public" || got.State != "candidate" {
			t.Fatalf("finding %+v", got)
		}
		if n := historyCount(t, ctx, pool, f.ID); n != before+1 {
			t.Fatalf("history %d, want %d", n, before+1)
		}
		var actor, reason string
		if err := pool.QueryRow(ctx, `SELECT actor, reason FROM aleef_finding_history WHERE finding_id=$1 ORDER BY id DESC LIMIT 1`, f.ID).Scan(&actor, &reason); err != nil || actor != "carol" || !strings.Contains(reason, "known_public") {
			t.Fatalf("history %q %q %v", actor, reason, err)
		}
		if err := s.SetPriorKnowledge(ctx, f.ID, "zero-day", "carol"); err == nil {
			t.Fatal("junk value accepted")
		}
		if err := s.SetPriorKnowledge(ctx, "missing", "known_vendor", "carol"); err == nil {
			t.Fatal("missing finding accepted")
		}
		got, _ = s.GetFinding(ctx, f.ID)
		if got.PriorKnowledge != "known_public" {
			t.Fatalf("junk changed the value: %+v", got)
		}
	})
}

func TestEnsureSchemaIdempotentWithRegressions(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t-idem")
		if err := s.SaveRegression(ctx, f.ID, "ALEEF-REG-0042", []byte(`{}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := store.EnsureSchema(ctx, pool); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.GetRegression(ctx, f.ID); err != nil {
			t.Fatalf("regression lost by re-running EnsureSchema: %v", err)
		}
	})
}

// verifiedFinding returns a finding moved to verified.
func verifiedFinding(t *testing.T, ctx context.Context, s *store.Store, id string) store.Finding {
	t.Helper()
	_, f := newFinding(t, ctx, s, id)
	if err := s.MarkVerified(ctx, f.ID, "hash-"+id, "test"); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestVerifiedWithoutRegressionIsDetectedAndNeverListedAsVerified(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		with := verifiedFinding(t, ctx, s, "t-with")
		without := verifiedFinding(t, ctx, s, "t-without")
		if err := s.SaveRegression(ctx, with.ID, "ALEEF-REG-0100", []byte(`{}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		// just verified: inside the grace window, so not reported yet
		if got, err := s.ListVerifiedWithoutRegression(ctx, ""); err != nil || len(got) != 0 {
			t.Fatalf("fresh finding reported: %v %v", got, err)
		}
		if _, err := pool.Exec(ctx, `UPDATE aleef_findings SET updated_at = NOW() - interval '1 hour'`); err != nil {
			t.Fatal(err)
		}
		got, err := s.ListVerifiedWithoutRegression(ctx, "")
		if err != nil || len(got) != 1 || got[0].ID != without.ID {
			t.Fatalf("without-regression list: %v %v", got, err)
		}
		if scoped, _ := s.ListVerifiedWithoutRegression(ctx, without.RunID); len(scoped) != 1 {
			t.Fatalf("run-scoped list: %v", scoped)
		}
		if scoped, _ := s.ListVerifiedWithoutRegression(ctx, with.RunID); len(scoped) != 0 {
			t.Fatalf("other run's list: %v", scoped)
		}
		// the presentable verified list never contains the unregressed finding
		for _, run := range []string{"", with.RunID, without.RunID} {
			vs, err := s.ListVerifiedWithRegression(ctx, run)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range vs {
				if v.ID == without.ID {
					t.Fatalf("unregressed finding listed as verified (run %q)", run)
				}
			}
		}
		vs, _ := s.ListVerifiedWithRegression(ctx, with.RunID)
		if len(vs) != 1 || vs[0].ID != with.ID {
			t.Fatalf("regressed finding missing: %v", vs)
		}
		// demoting the unregressed one removes it from the detector
		if err := s.SetFindingState(ctx, without.ID, "unconfirmed", "regression missing", "x"); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.ListVerifiedWithoutRegression(ctx, ""); len(got) != 0 {
			t.Fatalf("still reported: %v", got)
		}
	})
}

func TestSaveRegressionDuplicateRegressionIDIsClear(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, a := newFinding(t, ctx, s, "t-dup-a")
		_, b := newFinding(t, ctx, s, "t-dup-b")
		if err := s.SaveRegression(ctx, a.ID, "ALEEF-REG-0500", []byte(`{}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		err := s.SaveRegression(ctx, b.ID, "ALEEF-REG-0500", []byte(`{}`), nil, "")
		if err == nil || !strings.Contains(err.Error(), "already used by another finding") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestExhaustedSerialIsDistinguished(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		if _, err := pool.Exec(ctx, `SELECT setval('aleef_regression_seq', 9999)`); err != nil {
			t.Fatal(err)
		}
		_, err := s.NextRegressionSeq(ctx)
		_, _ = pool.Exec(ctx, `SELECT setval('aleef_regression_seq', 1, false)`)
		if !errors.Is(err, store.ErrRegressionSerialsExhausted) {
			t.Fatalf("err %v", err)
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := s.NextRegressionSeq(cctx); err == nil || errors.Is(err, store.ErrRegressionSerialsExhausted) {
			t.Fatalf("other failure reported as exhaustion: %v", err)
		}
	})
}

func TestPriorKnowledgeValuesMatchSchemaAndSetter(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t-pkv")
		for _, v := range store.PriorKnowledgeValues {
			if err := s.SetPriorKnowledge(ctx, f.ID, v, "x"); err != nil {
				t.Fatalf("setter rejects %q: %v", v, err)
			}
			if _, err := pool.Exec(ctx, `UPDATE aleef_findings SET prior_knowledge=$2 WHERE id=$1`, f.ID, v); err != nil {
				t.Fatalf("schema rejects %q: %v", v, err)
			}
		}
		if _, err := pool.Exec(ctx, `UPDATE aleef_findings SET prior_knowledge='made_up' WHERE id=$1`, f.ID); err == nil {
			t.Fatal("schema accepts a value outside the list")
		}
		if len(store.PriorKnowledgeValues) != 4 {
			t.Fatalf("values %v", store.PriorKnowledgeValues)
		}
	})
}
