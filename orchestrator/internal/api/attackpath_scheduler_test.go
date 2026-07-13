package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunScheduledAPCollection_NotConfigured(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		hub := ws.NewHub()
		// No panic and no dispatch when the schedule singleton row was never created.
		runScheduledAPCollection(context.Background(), pool, hub)
	})
}

func TestRunScheduledAPCollection_Disabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAttackPathSchedule(t, pool, false, 60, nil)
		hub := ws.NewHub()
		agent := startFakeAgent(t, hub, "sched-disabled-agent")
		defer agent.Disconnect(t)

		runScheduledAPCollection(context.Background(), pool, hub)

		assertNoDispatch(t, agent)
	})
}

func TestRunScheduledAPCollection_IntervalNotElapsed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAttackPathSchedule(t, pool, true, 60, nil)
		recent := time.Now().Add(-time.Minute) // interval is 60min, ran 1min ago
		pool.Exec(context.Background(), `UPDATE attackpath_schedule SET last_run_at=$1 WHERE id=1`, recent)

		hub := ws.NewHub()
		agent := startFakeAgent(t, hub, "sched-recent-agent")
		defer agent.Disconnect(t)

		runScheduledAPCollection(context.Background(), pool, hub)

		assertNoDispatch(t, agent)
	})
}

func TestRunScheduledAPCollection_NoConnectedAgents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAttackPathSchedule(t, pool, true, 60, nil)
		hub := ws.NewHub()

		// No agents connected — must not panic, and last_run_at must stay unset
		// (a scheduler tick with zero reachable agents didn't actually run).
		runScheduledAPCollection(context.Background(), pool, hub)

		var lastRunAt *time.Time
		pool.QueryRow(context.Background(), `SELECT last_run_at FROM attackpath_schedule WHERE id=1`).Scan(&lastRunAt)
		if lastRunAt != nil {
			t.Fatalf("last_run_at = %v, want nil (no agents reached)", lastRunAt)
		}
	})
}

// TestRunScheduledAPCollection_DispatchesAndUpdatesLastRunAt pins the happy
// path: enabled + interval elapsed + a connected agent → the command is
// actually delivered over the real WS path and last_run_at advances.
func TestRunScheduledAPCollection_DispatchesAndUpdatesLastRunAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAttackPathSchedule(t, pool, true, 60, []string{"10.0.0.1"})
		hub := ws.NewHub()
		agent := startFakeAgent(t, hub, "sched-fire-agent")
		defer agent.Disconnect(t)

		runScheduledAPCollection(context.Background(), pool, hub)

		env := agent.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandAttackPathCollect {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgCommandAttackPathCollect)
		}
		var data map[string]any
		json.Unmarshal(env.Data, &data)
		targets, _ := data["targets"].([]any)
		if len(targets) != 1 || targets[0] != "10.0.0.1" {
			t.Fatalf("dispatched targets = %+v, want [10.0.0.1]", data["targets"])
		}

		var lastRunAt *time.Time
		pool.QueryRow(context.Background(), `SELECT last_run_at FROM attackpath_schedule WHERE id=1`).Scan(&lastRunAt)
		if lastRunAt == nil {
			t.Fatal("expected last_run_at to be stamped after a successful dispatch")
		}
	})
}

func seedAttackPathSchedule(t *testing.T, pool *pgxpool.Pool, enabled bool, intervalMinutes int, targets []string) {
	t.Helper()
	raw, _ := json.Marshal(targets)
	if raw == nil {
		raw = []byte("[]")
	}
	_, err := pool.Exec(context.Background(),
		`INSERT INTO attackpath_schedule (id, enabled, interval_minutes, targets, segment, run_sharphound)
		 VALUES (1,$1,$2,$3,'',false)
		 ON CONFLICT (id) DO UPDATE SET enabled=$1, interval_minutes=$2, targets=$3`,
		enabled, intervalMinutes, raw)
	if err != nil {
		t.Fatalf("seedAttackPathSchedule: %v", err)
	}
}

// assertNoDispatch confirms no real command arrives, ignoring the
// connectivity-probe frame startFakeAgent's own handshake leaves buffered.
func assertNoDispatch(t *testing.T, agent *fakeAgent) {
	t.Helper()
	select {
	case env := <-agent.received:
		if env.Type == "__test_probe__" {
			assertNoDispatch(t, agent)
			return
		}
		t.Fatalf("expected no dispatch, got message type %q", env.Type)
	case <-time.After(300 * time.Millisecond):
	}
}
