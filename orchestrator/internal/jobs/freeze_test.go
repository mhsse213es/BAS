package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateFreeze_PersistsAndRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC()
		to := from.Add(48 * time.Hour)

		created, err := store.CreateFreeze(ctx, AgentFreeze{
			AgentID: "freeze-agent-1", FromAt: from, ToAt: to, Reason: "Q3 audit change-freeze", CreatedBy: "admin-1",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}
		if created.ID == "" || created.Reason != "Q3 audit change-freeze" {
			t.Fatalf("created = %+v, want non-empty ID and the given reason", created)
		}

		got, err := store.ListFreezesForAgent(ctx, "freeze-agent-1")
		if err != nil {
			t.Fatalf("ListFreezesForAgent: %v", err)
		}
		if len(got) != 1 || got[0].ID != created.ID {
			t.Fatalf("ListFreezesForAgent() = %+v, want 1 row matching %s", got, created.ID)
		}
	})
}

func TestIsAgentFrozen_ActiveWindowReturnsTrue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC().Add(-1 * time.Hour)
		to := time.Now().UTC().Add(1 * time.Hour)
		if _, err := store.CreateFreeze(ctx, AgentFreeze{AgentID: "freeze-agent-2", FromAt: from, ToAt: to, Reason: "maintenance"}); err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		frozen, reason, err := store.IsAgentFrozen(ctx, "freeze-agent-2")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if !frozen || reason != "maintenance" {
			t.Errorf("frozen=%v reason=%q, want true/maintenance", frozen, reason)
		}
	})
}

func TestIsAgentFrozen_ExpiredWindowReturnsFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC().Add(-48 * time.Hour)
		to := time.Now().UTC().Add(-24 * time.Hour)
		if _, err := store.CreateFreeze(ctx, AgentFreeze{AgentID: "freeze-agent-3", FromAt: from, ToAt: to, Reason: "past freeze"}); err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		frozen, _, err := store.IsAgentFrozen(ctx, "freeze-agent-3")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false -- the freeze window already ended")
		}
	})
}

func TestIsAgentFrozen_NoFreezeReturnsFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		frozen, _, err := store.IsAgentFrozen(context.Background(), "freeze-agent-never-frozen")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false -- this agent has no freeze rows at all")
		}
	})
}

func TestDeleteFreeze_LiftsItEarly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC().Add(-1 * time.Hour)
		to := time.Now().UTC().Add(1 * time.Hour)
		created, err := store.CreateFreeze(ctx, AgentFreeze{AgentID: "freeze-agent-4", FromAt: from, ToAt: to, Reason: "will be lifted"})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		if err := store.DeleteFreeze(ctx, created.ID); err != nil {
			t.Fatalf("DeleteFreeze: %v", err)
		}
		frozen, _, err := store.IsAgentFrozen(ctx, "freeze-agent-4")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false -- the freeze was deleted")
		}
	})
}
