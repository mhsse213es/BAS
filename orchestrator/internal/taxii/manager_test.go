package taxii

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestManagerStart_LaunchesOneSchedulerPerEnabledConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.Create(ctx, ConnectorConfig{Name: "MgrEnabled", ServerURL: "http://127.0.0.1:1", Enabled: true}); err != nil {
			t.Fatalf("create enabled: %v", err)
		}
		if _, err := store.Create(ctx, ConnectorConfig{Name: "MgrDisabled", ServerURL: "http://127.0.0.1:1", Enabled: false}); err != nil {
			t.Fatalf("create disabled: %v", err)
		}
		m := NewManager(pool, store)
		if err := m.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer m.Stop()
		m.mu.Lock()
		n := len(m.schedulers)
		m.mu.Unlock()
		if n != 1 {
			t.Fatalf("running scheduler count = %d, want 1 (only the enabled config)", n)
		}
	})
}

func TestManagerReconcile_StopsRemovedAndStartsNewlyEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		m := NewManager(pool, store)
		if err := m.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer m.Stop()
		m.mu.Lock()
		n0 := len(m.schedulers)
		m.mu.Unlock()
		if n0 != 0 {
			t.Fatalf("expected 0 schedulers with no configs yet, got %d", n0)
		}

		cfg, err := store.Create(ctx, ConnectorConfig{Name: "NewlyEnabled", ServerURL: "http://127.0.0.1:1", Enabled: true})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := m.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		m.mu.Lock()
		n1 := len(m.schedulers)
		m.mu.Unlock()
		if n1 != 1 {
			t.Fatalf("expected 1 scheduler after Reconcile with a new enabled config, got %d", n1)
		}

		if err := store.Delete(ctx, cfg.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if err := m.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile after delete: %v", err)
		}
		m.mu.Lock()
		n2 := len(m.schedulers)
		m.mu.Unlock()
		if n2 != 0 {
			t.Fatalf("expected 0 schedulers after deleting the only config, got %d", n2)
		}
	})
}

func TestManagerTriggerSync_RunsOneSyncForOneConnector(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "TriggerTest", ServerURL: "http://127.0.0.1:1", Enabled: false})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		m := NewManager(pool, store)
		_ = m.TriggerSync(ctx, cfg.ID) // expected to error (unreachable server) -- we're only checking it recorded a result, not that it succeeded
		got, err := store.Get(ctx, cfg.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollAt == nil {
			t.Fatal("TriggerSync did not record a poll attempt")
		}
	})
}
