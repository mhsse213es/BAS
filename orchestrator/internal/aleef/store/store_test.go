package store_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/apibas/runner"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func withStore(t *testing.T, fn func(ctx context.Context, pool *pgxpool.Pool, s *store.Store)) {
	t.Helper()
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := store.EnsureSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		fn(ctx, pool, store.New(pool))
	})
}

func sampleTest(id string) generate.Test {
	return generate.Test{ID: id, Property: "P-AUTHZ", Params: map[string]string{"role": "viewer"}, Covered: true}
}

func sampleResult() exec.Result {
	return exec.Result{Verdict: exec.Verdict{Finding: exec.FindingYes, Reason: "other tenant object returned", Oracle: "status"}}
}

// newFinding creates a run, saves the test and returns a candidate finding.
func newFinding(t *testing.T, ctx context.Context, s *store.Store, testID string) (string, store.Finding) {
	t.Helper()
	runID, err := s.CreateRun(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	tst := sampleTest(testID)
	if err := s.SaveTest(ctx, runID, tst); err != nil {
		t.Fatal(err)
	}
	f, err := s.CreateFinding(ctx, runID, tst, sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	return runID, f
}

func historyCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM aleef_finding_history WHERE finding_id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEnsureSchemaIdempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for i := 0; i < 2; i++ {
			if err := store.EnsureSchema(context.Background(), pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
	})
}

func TestFindingStateChangeAppendsHistory(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t1")
		if f.State != "candidate" || f.PriorKnowledge != "not_checked" || !f.Covered {
			t.Fatalf("new finding %+v", f)
		}
		if n := historyCount(t, ctx, pool, f.ID); n != 1 {
			t.Fatalf("history after create = %d, want 1", n)
		}
		if err := s.SetFindingState(ctx, f.ID, "unconfirmed", "could not reproduce", "alice"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFindingState(ctx, f.ID, "rejected", "false positive", "alice"); err != nil {
			t.Fatal(err)
		}
		if n := historyCount(t, ctx, pool, f.ID); n != 3 {
			t.Fatalf("history = %d, want 3", n)
		}
		var prev, next, reason, actor string
		err := pool.QueryRow(ctx, `SELECT previous_state,new_state,reason,actor FROM aleef_finding_history
			WHERE finding_id=$1 ORDER BY id DESC LIMIT 1`, f.ID).Scan(&prev, &next, &reason, &actor)
		if err != nil || prev != "unconfirmed" || next != "rejected" || reason != "false positive" || actor != "alice" {
			t.Fatalf("last history %q %q %q %q err=%v", prev, next, reason, actor, err)
		}
		got, err := s.GetFinding(ctx, f.ID)
		if err != nil || got.State != "rejected" {
			t.Fatalf("get %+v err=%v", got, err)
		}
	})
}

func TestVerifiedRequiresEvidenceHash(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t1")
		if err := s.MarkVerified(ctx, f.ID, "", "verifier"); err == nil {
			t.Fatal("MarkVerified with empty hash must fail")
		}
		got, _ := s.GetFinding(ctx, f.ID)
		if got.State != "candidate" {
			t.Fatalf("state changed to %q after failed verify", got.State)
		}
		if _, err := pool.Exec(ctx, `UPDATE aleef_findings SET state='verified', evidence_hash='' WHERE id=$1`, f.ID); err == nil {
			t.Fatal("raw UPDATE to verified with empty hash must violate the CHECK")
		}
		if _, err := pool.Exec(ctx, `UPDATE aleef_findings SET state='verified', evidence_hash=NULL WHERE id=$1`, f.ID); err == nil {
			t.Fatal("raw UPDATE to verified with NULL hash must violate the CHECK")
		}
		if err := s.MarkVerified(ctx, f.ID, "sha256:abc", "verifier"); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetFinding(ctx, f.ID)
		if got.State != "verified" || got.EvidenceHash != "sha256:abc" {
			t.Fatalf("got %+v", got)
		}
		if n := historyCount(t, ctx, pool, f.ID); n != 2 {
			t.Fatalf("history = %d, want 2", n)
		}
	})
}

func TestSetFindingStateRejectsVerified(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t1")
		if err := s.SetFindingState(ctx, f.ID, "verified", "trust me", "alice"); err == nil {
			t.Fatal("SetFindingState must reject verified")
		}
		if err := s.SetFindingState(ctx, f.ID, "bogus", "x", "alice"); err == nil {
			t.Fatal("unknown state must be rejected")
		}
		got, _ := s.GetFinding(ctx, f.ID)
		if got.State != "candidate" {
			t.Fatalf("state = %q", got.State)
		}
	})
}

func TestHistoryIsAppendOnly(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t1")
		if _, err := pool.Exec(ctx, `UPDATE aleef_finding_history SET reason='edited' WHERE finding_id=$1`, f.ID); err == nil {
			t.Fatal("UPDATE on history must be rejected")
		}
		if _, err := pool.Exec(ctx, `DELETE FROM aleef_finding_history WHERE finding_id=$1`, f.ID); err == nil {
			t.Fatal("DELETE on history must be rejected")
		}
		if n := historyCount(t, ctx, pool, f.ID); n != 1 {
			t.Fatalf("history = %d, want 1", n)
		}
	})
}

func TestVerifiedCannotRegressToCandidate(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		_, f := newFinding(t, ctx, s, "t1")
		if err := s.MarkVerified(ctx, f.ID, "sha256:abc", "verifier"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFindingState(ctx, f.ID, "candidate", "oops", "alice"); err == nil {
			t.Fatal("verified -> candidate must be rejected")
		}
		if _, err := pool.Exec(ctx, `UPDATE aleef_findings SET state='candidate' WHERE id=$1`, f.ID); err == nil {
			t.Fatal("raw verified -> candidate must be rejected by the DB")
		}
		if err := s.SetFindingState(ctx, f.ID, "rejected", "", "alice"); err == nil || !strings.Contains(err.Error(), "reason") {
			t.Fatalf("leaving verified without a reason must fail, got %v", err)
		}
		if err := s.SetFindingState(ctx, f.ID, "rejected", "retest showed fixed", "alice"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestListFindingsSeparatesCandidatesFromVerified(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		runID, err := s.CreateRun(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		mk := func(id string) store.Finding {
			tst := sampleTest(id)
			if err := s.SaveTest(ctx, runID, tst); err != nil {
				t.Fatal(err)
			}
			f, err := s.CreateFinding(ctx, runID, tst, sampleResult())
			if err != nil {
				t.Fatal(err)
			}
			return f
		}
		a, b, c, d := mk("a"), mk("b"), mk("c"), mk("d")
		if err := s.MarkVerified(ctx, b.ID, "h", "verifier"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFindingState(ctx, c.ID, "rejected", "fp", "alice"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFindingState(ctx, d.ID, "unconfirmed", "flaky", "alice"); err != nil {
			t.Fatal(err)
		}
		cands, ver, others, err := s.ListFindings(ctx, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(cands) != 1 || cands[0].ID != a.ID || len(ver) != 1 || ver[0].ID != b.ID || len(others) != 2 {
			t.Fatalf("cands=%d ver=%d others=%d", len(cands), len(ver), len(others))
		}
	})
}

func TestSaveResultRoundTrip(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		runID, err := s.CreateRun(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		tst := sampleTest("t1")
		if err := s.SaveTest(ctx, runID, tst); err != nil {
			t.Fatal(err)
		}
		res := sampleResult()
		res.Report = runner.Report{DetectionProvenance: "fixture"}
		if err := s.SaveResult(ctx, runID, tst, 1, res); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveResult(ctx, runID, tst, 2, res); err != nil {
			t.Fatal(err)
		}
		var finding, reason, oracle, prov string
		var n int
		err = pool.QueryRow(ctx, `SELECT count(*) FROM aleef_results WHERE run_id=$1 AND test_id='t1'`, runID).Scan(&n)
		if err != nil || n != 2 {
			t.Fatalf("results = %d err=%v", n, err)
		}
		err = pool.QueryRow(ctx, `SELECT verdict_finding, verdict_reason, verdict_oracle, report->>'detection_provenance'
			FROM aleef_results WHERE run_id=$1 AND test_id='t1' AND exec_no=2`, runID).Scan(&finding, &reason, &oracle, &prov)
		if err != nil || finding != "yes" || reason != "other tenant object returned" || oracle != "status" || prov != "fixture" {
			t.Fatalf("row %q %q %q %q err=%v", finding, reason, oracle, prov, err)
		}
	})
}

func TestEngagementRoundTrip(t *testing.T) {
	withStore(t, func(ctx context.Context, pool *pgxpool.Pool, s *store.Store) {
		id, err := s.CreateEngagement(ctx, store.Engagement{Customer: "acme", Environment: "uat",
			ApprovedHosts: []string{"uat.acme.test"}, Window: "2026-11-01/2026-11-05", Approver: "bob", Body: []byte(`{"k":1}`)})
		if err != nil {
			t.Fatal(err)
		}
		e, err := s.GetEngagement(ctx, id)
		if err != nil || e.Customer != "acme" || len(e.ApprovedHosts) != 1 || e.Approver != "bob" || !strings.Contains(string(e.Body), `"k"`) {
			t.Fatalf("got %+v err=%v", e, err)
		}
	})
}
