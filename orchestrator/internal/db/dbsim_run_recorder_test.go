package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim"
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

// A dbsim run's scenario_runs row must end when its job reaches a terminal state,
// in the same transaction as the job; until then it holds the agent's running slot.
func TestDBSimJobTerminalTransitionFinishesRunRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureDBSimJobSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		agent := "1123456789abcdef"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ($1) ON CONFLICT DO NOTHING`, agent); err != nil {
			t.Fatalf("enrol agent: %v", err)
		}
		st := db.DBSimJobStore{Pool: pool}
		if err := st.Create(ctx, dbsimJob("run-fin", "t1", agent), dbsimAudit("job_create")); err != nil {
			t.Fatal(err)
		}
		if err := (db.DBSimRunRecorder{Pool: pool}).InsertRun(ctx, "run-fin", "dbsim-run", agent, "x", "u1", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		// The per-agent running index refuses a normal run while the dbsim run is live.
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (id, scenario_id, agent_id, status, mode, started_at) VALUES ('normal-run', 'x', $1, 'running', 'posture', NOW())`, agent); err == nil {
			t.Fatal("a normal run started on an agent that has a live dbsim run")
		}
		if moved, err := st.Transition(ctx, "run-fin", []dbsim.JobStatus{dbsim.JobPending}, dbsim.JobRunning, "", dbsimAudit("run_dispatched")); err != nil || !moved {
			t.Fatalf("to running: moved=%v err=%v", moved, err)
		}
		if moved, err := st.Transition(ctx, "run-fin", []dbsim.JobStatus{dbsim.JobRunning}, dbsim.JobCompleted, "", dbsimAudit("run_completed")); err != nil || !moved {
			t.Fatalf("to completed: moved=%v err=%v", moved, err)
		}
		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT status, completed_at FROM scenario_runs WHERE id = 'run-fin'`).Scan(&status, &completedAt); err != nil {
			t.Fatal(err)
		}
		if status != "completed" || completedAt == nil {
			t.Fatalf("run row status=%q completed_at=%v, want completed with a finish time", status, completedAt)
		}
		// Once the dbsim run has finished, the agent is free for a normal run again.
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (id, scenario_id, agent_id, status, mode, started_at) VALUES ('normal-run', 'x', $1, 'running', 'posture', NOW())`, agent); err != nil {
			t.Fatalf("agent still blocked after the dbsim run finished: %v", err)
		}
	})
}
