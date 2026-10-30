package verify

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/testutil"
)

func TestVerifierIntegrationWithPostgres(t *testing.T) {
	sharedDB := testutil.MustSharedTestDB()
	defer sharedDB.Cleanup()

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := store.EnsureSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		st := store.New(pool)
		history := func(id string) []string {
			rows, err := pool.Query(ctx, `SELECT new_state FROM aleef_finding_history WHERE finding_id=$1 ORDER BY id`, id)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var out []string
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err != nil {
					t.Fatal(err)
				}
				out = append(out, s)
			}
			return out
		}
		prepare := func(x generate.Test) string {
			runID, err := st.CreateRun(ctx, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, tt := range []generate.Test{x, *x.OwnerControl, *x.NegativeControl} {
				if err := st.SaveTest(ctx, runID, tt); err != nil {
					t.Fatal(err)
				}
			}
			return runID
		}
		x := ownTest(t)

		// stable flaw -> verified in the database
		ty := newToy()
		ty.readFlaw = stable
		runID := prepare(x)
		v, err := New(newEnv(t, ty), st, Options{RunID: runID}).Verify(ctx, x)
		if err != nil {
			t.Fatal(err)
		}
		if v.State != StateVerified {
			t.Fatalf("verdict %+v", v)
		}
		_, verified, _, err := st.ListFindings(ctx, runID)
		if err != nil || len(verified) != 1 || verified[0].EvidenceHash != v.EvidenceHash || verified[0].State != "verified" {
			t.Fatalf("verified findings %+v err %v", verified, err)
		}
		if h := history(verified[0].ID); len(h) != 2 || h[0] != "candidate" || h[1] != "verified" {
			t.Fatalf("history %v", h)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM aleef_results WHERE run_id=$1`, runID).Scan(&n); err != nil || n != 9 {
			t.Fatalf("results rows %d err %v", n, err)
		}

		// flaky flaw -> rejected
		fl := newToy()
		fl.readFlaw = func(n int) bool { return n%2 == 1 }
		runID2 := prepare(x)
		v, err = New(newEnv(t, fl), st, Options{RunID: runID2}).Verify(ctx, x)
		if err != nil {
			t.Fatal(err)
		}
		if v.State != StateRejected {
			t.Fatalf("flaky verdict %+v", v)
		}
		cands, ver, others, err := st.ListFindings(ctx, runID2)
		if err != nil || len(cands) != 0 || len(ver) != 0 || len(others) != 1 || others[0].State != "rejected" {
			t.Fatalf("flaky findings c=%v v=%v o=%v err=%v", cands, ver, others, err)
		}
		if h := history(others[0].ID); len(h) != 2 || h[0] != "candidate" || h[1] != "rejected" {
			t.Fatalf("history %v", h)
		}
	})
}
