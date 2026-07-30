package campaign

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestListWithRollups_ComputesLiveSummaryPerCampaign(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, created_by, targets, skips, tags, started_at)
			VALUES ('camp-1', 'Test Campaign', 'scn-1', 'Test Scenario', 'posture', 'tester', '["a1"]', '[]', '[]', NOW())`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, campaign_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'a1', 'camp-1', 'completed', '[]', NOW())`)

		got, err := ListWithRollups(ctx, pool)
		if err != nil {
			t.Fatalf("ListWithRollups: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("ListWithRollups() = %+v, want 1 campaign", got)
		}
		r := got[0]
		if r.ID != "camp-1" || r.Name != "Test Campaign" {
			t.Errorf("Rollup = %+v, want ID=camp-1 Name=Test Campaign", r)
		}
		if r.Summary.Status != "completed" {
			t.Errorf("Summary.Status = %q, want completed (matches DeriveStatus for one completed child, no skips)", r.Summary.Status)
		}
		if r.Summary.Dispatched != 1 {
			t.Errorf("Summary.Dispatched = %d, want 1", r.Summary.Dispatched)
		}
	})
}

func TestListWithRollups_EmptyFleet_ReturnsEmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ListWithRollups(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListWithRollups: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("ListWithRollups() = %+v, want empty", got)
		}
	})
}
