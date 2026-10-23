package campaign

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/testutil"
)

func TestCampaignIntegrationPostgres(t *testing.T) {
	sharedDB := testutil.MustSharedTestDB()
	defer sharedDB.Cleanup()

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := store.EnsureSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		st := store.New(pool)

		ty := newToy()
		ty.readFlaw = true
		cfg, _ := toyConfig(t, ty, st)
		rep, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if rep.Verified < 1 || rep.RunID == "" || rep.Halted != "" || len(rep.Orphans) != 0 {
			t.Fatalf("report: verified=%d run=%q halted=%q orphans=%v", rep.Verified, rep.RunID, rep.Halted, rep.Orphans)
		}
		_, verified, _, err := st.ListFindings(ctx, rep.RunID)
		if err != nil || len(verified) != rep.Verified {
			t.Fatalf("stored verified findings %d (report %d) err %v", len(verified), rep.Verified, err)
		}
		hashes := map[string]string{}
		for _, f := range rep.Findings {
			hashes[f.FindingID] = f.EvidenceHash
		}
		for _, f := range verified {
			if f.EvidenceHash == "" || hashes[f.ID] != f.EvidenceHash {
				t.Fatalf("finding %s: stored hash %q, report hash %q", f.ID, f.EvidenceHash, hashes[f.ID])
			}
		}
		// every verified finding has a stored regression that replays
		checked := 0
		for _, f := range verified {
			reg, err := st.GetRegression(ctx, f.ID)
			if err != nil || reg.RegressionID == "" || len(reg.BundleJSON) == 0 {
				t.Fatalf("finding %s: regression %+v err %v", f.ID, reg, err)
			}
			if checked < 2 {
				assertRegressionExecutable(t, reg.BundleJSON)
				checked++
			}
		}
		for _, f := range rep.Findings {
			if f.State == "verified" && (!f.OwnerControl || !f.NegativeControl) {
				t.Fatalf("verified finding %s without recorded passing controls", f.FindingID)
			}
			if f.State == "verified" && f.RegressionID == "" {
				t.Fatalf("report finding %s has no regression id", f.FindingID)
			}
		}
		// every test and both controls were stored before verification
		var tests int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM aleef_tests WHERE run_id=$1`, rep.RunID).Scan(&tests); err != nil || tests < rep.Total*3 {
			t.Fatalf("stored tests %d for %d generated (err %v)", tests, rep.Total, err)
		}
		var results int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM aleef_results WHERE run_id=$1`, rep.RunID).Scan(&results); err != nil || results == 0 {
			t.Fatalf("stored results %d err %v", results, err)
		}
		if ty.leftover() != 0 {
			t.Fatalf("%d objects left on the toy", ty.leftover())
		}
	})
}
