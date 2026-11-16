package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
)

// A change-freeze window holds every automatic starter, not only scheduled assessments. Each holds its work for the
// length of the window and starts it once the window is gone, so a freeze loses nothing.

func freezeNow(t *testing.T, store *jobs.Store) jobs.Blackout {
	t.Helper()
	now := time.Now().UTC()
	w, err := store.CreateBlackout(context.Background(), jobs.Blackout{
		Name: "EoD batch", Kind: "once",
		StartsAt: &[]time.Time{now.Add(-time.Hour)}[0], EndsAt: &[]time.Time{now.Add(time.Hour)}[0], CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("CreateBlackout: %v", err)
	}
	return w
}

func TestRunScheduledAPCollection_HeldByChangeFreezeThenFires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedAttackPathSchedule(t, pool, true, 60, []string{"10.0.0.1"})
		hub := ws.NewHub()
		agent := startFakeAgent(t, hub, "freeze-ap-agent")
		defer agent.Disconnect(t)

		store := jobs.NewStore(pool)
		w := freezeNow(t, store)

		runScheduledAPCollection(ctx, pool, hub)
		assertNoDispatch(t, agent)
		var lastRunAt *time.Time
		pool.QueryRow(ctx, `SELECT last_run_at FROM attackpath_schedule WHERE id=1`).Scan(&lastRunAt)
		if lastRunAt != nil {
			t.Fatalf("last_run_at = %v inside a freeze: the collection would not run when the window ends", lastRunAt)
		}

		if ok, err := store.DeleteBlackout(ctx, w.ID); !ok || err != nil {
			t.Fatalf("DeleteBlackout: %v %v", ok, err)
		}
		runScheduledAPCollection(ctx, pool, hub)
		if env := agent.WaitForMessage(t, 2*time.Second); env.Type != models.MsgCommandAttackPathCollect {
			t.Fatalf("after the window: message %q, want %q", env.Type, models.MsgCommandAttackPathCollect)
		}
	})
}

func TestAPIBASSchedulerTick_HeldByChangeFreezeThenRuns(t *testing.T) {
	hd := jobsHandler(t, true)
	hd.jobsStore = jobs.NewStore(sharedDB.Pool)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "freeze-run")
	if rec := putAs(t, h, "/api/apibas/targets/freeze-run/schedule", map[string]any{"every_hours": 1}, "admin", "admin1"); rec.Code != 200 {
		t.Fatalf("save: %d", rec.Code)
	}
	makeDue(t, "freeze-run")
	w := freezeNow(t, hd.jobsStore)

	hd.apibasSchedulerTick(ctx, time.Now().UTC())
	s, err := db.GetAPIBASSchedule(ctx, sharedDB.Pool, "freeze-run")
	if err != nil {
		t.Fatal(err)
	}
	if s.LastJobID != "" || s.LastResult != "" {
		t.Fatalf("a schedule ran inside a freeze: %+v", s)
	}

	if ok, err := hd.jobsStore.DeleteBlackout(ctx, w.ID); !ok || err != nil {
		t.Fatalf("DeleteBlackout: %v %v", ok, err)
	}
	hd.apibasSchedulerTick(ctx, time.Now().UTC())
	s, _ = db.GetAPIBASSchedule(ctx, sharedDB.Pool, "freeze-run")
	if s.LastJobID == "" {
		t.Fatalf("the held schedule did not run once the window ended: %+v", s)
	}
}

// A held revalidation tick must return before it reads tickets. The handler here has no database, so a tick that did
// not hold would panic on its first query.
func TestRevalidationTick_HeldByChangeFreezeTouchesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := jobs.NewStore(pool)
		freezeNow(t, store)
		h := &Handler{jobsStore: store} // db deliberately nil
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the revalidation tick was not held by the change freeze: %v", r)
			}
		}()
		h.runRevalidationTick(context.Background())
	})
}
