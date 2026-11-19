package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// Needs the Docker-backed test database (TestMain of this package): written and
// compiled here, run on a Docker-capable host.
func TestDBSimRunRecorderWritesRunRowAndActivityIgnoresDBSim(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		rec := db.DBSimRunRecorder{Pool: pool}
		act := db.DBSimAgentActivity{Pool: pool}
		agent := "0123456789abcdef"
		// scenario_runs.agent_id references agents: the agent must be enrolled first.
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ($1) ON CONFLICT DO NOTHING`, agent); err != nil {
			t.Fatalf("enrol agent: %v", err)
		}
		if err := rec.InsertRun(ctx, "dbsim-run-1", "dbsim-run", agent, "Database security simulation", "u1", time.Now().UTC()); err != nil {
			t.Fatalf("record: %v", err)
		}
		var kind, status string
		if err := pool.QueryRow(ctx, `SELECT execution_kind, status FROM scenario_runs WHERE id = 'dbsim-run-1'`).Scan(&kind, &status); err != nil {
			t.Fatalf("read row: %v", err)
		}
		if kind != "dbsim" || status != "running" {
			t.Fatalf("row kind=%q status=%q, want dbsim/running", kind, status)
		}
		busy, err := act.HasRunningScenario(ctx, agent)
		if err != nil || busy {
			t.Fatalf("a running dbsim row must not count as a normal scenario: busy=%v err=%v", busy, err)
		}
	})
}
