package detect

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedRun inserts a completed scenario run whose raw detections are non-empty, aged by the given days.
func seedRun(t *testing.T, pool *pgxpool.Pool, id string, ageDays int) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scenario_runs (id, agent_id, scenario_id, status, results, detections_raw, completed_at)
		VALUES ($1, 'agent-retention', 'scn-retention', 'completed', '[]', '[{"eventId":1}]',
		        NOW() - make_interval(days => $2))`, id, ageDays)
	if err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func rawOf(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var raw string
	if err := pool.QueryRow(context.Background(), `SELECT detections_raw::text FROM scenario_runs WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return raw
}

// Raw alerts must survive for the whole RawRetentionDays window. A run 179 days old is inside the 180-day
// minimum and must keep its alerts; a run 200 days old is past the window and is pruned.
func TestPrune_KeepsRawAlertsInsideTheMinimumWindow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname) VALUES ('agent-retention', 'HOST-R')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		seedRun(t, pool, "run-179", 179)
		seedRun(t, pool, "run-200", 200)
		seedRun(t, pool, "run-100", 100)

		prune(context.Background(), pool)

		if got := rawOf(t, pool, "run-179"); got == "[]" {
			t.Errorf("run 179 days old lost its raw alerts; they must be kept to 180 days")
		}
		if got := rawOf(t, pool, "run-100"); got == "[]" {
			t.Errorf("run 100 days old lost its raw alerts")
		}
		if got := rawOf(t, pool, "run-200"); got != "[]" {
			t.Errorf("run 200 days old kept its raw alerts %s; past the window they should be pruned", got)
		}
	})
}
