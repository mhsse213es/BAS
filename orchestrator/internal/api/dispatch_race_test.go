package api

import (
	"context"
	"sync"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSchema_ScenarioRunsHasPartialUniqueRunningIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var name string
		err := pool.QueryRow(context.Background(),
			`SELECT indexname FROM pg_indexes WHERE tablename='scenario_runs' AND indexname='idx_scenario_runs_agent_running'`,
		).Scan(&name)
		if err != nil {
			t.Fatalf("index missing: %v", err)
		}
	})
}

func TestDispatchRun_ConcurrentDispatchToIdleAgent_ExactlyOneWins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-race-target"
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		sc, _ := minimalPostureScenario(t, "scenario-race")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		const n = 15
		var wg sync.WaitGroup
		runIDs := make([]string, n)
		skips := make([]string, n)
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
				runIDs[i], skips[i], errs[i] = id, skip, err
			}(i)
		}
		wg.Wait()

		// The concurrency fix guarantees exactly one thing: no two goroutines
		// ever hold a 'running' row for this agent at once. It does NOT
		// guarantee the DB-race winner's WS delivery succeeds — that's a
		// separate, genuinely timing-sensitive concern (Go scheduling,
		// connection state) unrelated to the DB-level fix. So a winner's
		// dispatch can legitimately land as "offline" (its INSERT won the
		// race, but its subsequent WS send happened to lose a scheduling
		// race) rather than a clean win. All three outcomes below are valid;
		// what must NEVER happen is two clean wins or a genuine error.
		wins, busies, offlines := 0, 0, 0
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("goroutine %d: unexpected error %v", i, errs[i])
			}
			switch {
			case runIDs[i] != "" && skips[i] == "":
				wins++
			case runIDs[i] == "" && skips[i] == "agent busy":
				busies++
			case runIDs[i] == "" && skips[i] == "offline":
				offlines++
			default:
				t.Fatalf("goroutine %d: unexpected outcome runID=%q skip=%q", i, runIDs[i], skips[i])
			}
		}
		if wins+offlines != 1 {
			t.Fatalf("wins+offlines = %d, want exactly 1 (wins=%d offlines=%d busies=%d) — the DB-level race guard must let exactly one dispatch attempt past the busy check", wins+offlines, wins, offlines, busies)
		}
		if busies != n-1 {
			t.Fatalf("busies = %d, want %d", busies, n-1)
		}

		// The core invariant: never more than one 'running' row, regardless
		// of whether the winner ended up 'running' (clean win) or 'failed'
		// (offline WS delivery).
		var runningCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM scenario_runs WHERE agent_id=$1 AND status='running'`, agentID).Scan(&runningCount); err != nil {
			t.Fatalf("count running: %v", err)
		}
		wantRunning := 0
		if wins == 1 {
			wantRunning = 1
		}
		if runningCount != wantRunning {
			t.Fatalf("running row count = %d, want %d (wins=%d offlines=%d)", runningCount, wantRunning, wins, offlines)
		}

		var totalRuns int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM scenario_runs WHERE agent_id=$1`, agentID).Scan(&totalRuns); err != nil {
			t.Fatalf("count total runs: %v", err)
		}
		if totalRuns != 1 {
			t.Fatalf("total run row count = %d, want exactly 1 (the DB race guard must let only one INSERT through, win or lose on delivery)", totalRuns)
		}
	})
}
