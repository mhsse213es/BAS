package openaev

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestStore_UpsertThenGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := db.EnsureSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureSchema: %v", err)
		}
		if err := db.EnsureContentSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureContentSchema: %v", err)
		}
		store := NewSQLStore(pool)

		scenario := Scenario{
			OpenAEVScenarioID: "sc-store-001",
			Name:              "Ransomware Drill",
			TechniqueIDs:      []string{"T1486"},
		}
		detail := Detail{Description: "test"}

		if err := store.Upsert(context.Background(), scenario, detail, "hash-a", 100, 1); err != nil {
			t.Fatalf("Upsert: %v", err)
		}

		got, gotDetail, found, err := store.Get(context.Background(), "sc-store-001")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !found {
			t.Fatal("expected scenario to be found after Upsert")
		}
		if got.Name != "Ransomware Drill" {
			t.Errorf("Name = %q", got.Name)
		}
		if gotDetail.Description != "test" {
			t.Errorf("Detail.Description = %q", gotDetail.Description)
		}
	})
}

func TestStore_UpsertSameHashDoesNotBumpRevision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-store-002", Name: "A"}
		store.Upsert(context.Background(), scenario, Detail{}, "hash-same", 10, 1)
		store.Upsert(context.Background(), scenario, Detail{}, "hash-same", 10, 1)

		var revision int
		pool.QueryRow(context.Background(),
			`SELECT sync_revision FROM openaev_scenarios WHERE openaev_scenario_id = $1`, "sc-store-002").
			Scan(&revision)
		if revision != 1 {
			t.Errorf("sync_revision = %d, want 1 (unchanged hash must not bump it)", revision)
		}
	})
}

func TestStore_UpsertDifferentHashBumpsRevision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-store-003", Name: "A"}
		store.Upsert(context.Background(), scenario, Detail{}, "hash-1", 10, 1)
		store.Upsert(context.Background(), scenario, Detail{}, "hash-2", 10, 1)

		var revision int
		pool.QueryRow(context.Background(),
			`SELECT sync_revision FROM openaev_scenarios WHERE openaev_scenario_id = $1`, "sc-store-003").
			Scan(&revision)
		if revision != 2 {
			t.Errorf("sync_revision = %d, want 2 (changed hash must bump it)", revision)
		}
	})
}

func TestStore_SyncState_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		_, _, found, err := store.SyncState(context.Background(), "no-such-scenario")
		if err != nil {
			t.Fatalf("SyncState: %v", err)
		}
		if found {
			t.Error("expected found=false for a scenario never synced")
		}
	})
}

func TestStore_UpsertPersistsSourceType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-sourcetype-001", Name: "A", SourceType: "exercise"}
		if err := store.Upsert(context.Background(), scenario, Detail{}, "hash-a", 10, 1); err != nil {
			t.Fatalf("Upsert: %v", err)
		}

		got, _, found, err := store.Get(context.Background(), "sc-sourcetype-001")
		if err != nil || !found {
			t.Fatalf("Get: found=%v err=%v", found, err)
		}
		if got.SourceType != "exercise" {
			t.Errorf("SourceType = %q, want exercise", got.SourceType)
		}
	})
}

func TestStore_UpsertDefaultsEmptySourceTypeToScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-sourcetype-002", Name: "A"} // SourceType left unset
		store.Upsert(context.Background(), scenario, Detail{}, "hash-b", 10, 1)

		got, _, _, _ := store.Get(context.Background(), "sc-sourcetype-002")
		if got.SourceType != "scenario" {
			t.Errorf("SourceType = %q, want scenario (default)", got.SourceType)
		}
	})
}

func TestStore_ListFiltersBySourceType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		store.Upsert(context.Background(), Scenario{OpenAEVScenarioID: "sc-list-scn", Name: "Scn", SourceType: "scenario"}, Detail{}, "h1", 10, 1)
		store.Upsert(context.Background(), Scenario{OpenAEVScenarioID: "sc-list-exc", Name: "Exc", SourceType: "exercise"}, Detail{}, "h2", 10, 1)

		scenarios, err := store.List(context.Background(), "scenario")
		if err != nil {
			t.Fatalf("List(scenario): %v", err)
		}
		for _, s := range scenarios {
			if s.OpenAEVScenarioID == "sc-list-exc" {
				t.Error("List(\"scenario\") must not include an exercise-sourced row")
			}
		}

		exercises, err := store.List(context.Background(), "exercise")
		if err != nil {
			t.Fatalf("List(exercise): %v", err)
		}
		found := false
		for _, s := range exercises {
			if s.OpenAEVScenarioID == "sc-list-exc" {
				found = true
			}
		}
		if !found {
			t.Error("List(\"exercise\") must include the exercise-sourced row")
		}

		all, err := store.List(context.Background(), "")
		if err != nil {
			t.Fatalf("List(\"\"): %v", err)
		}
		if len(all) < 2 {
			t.Errorf("List(\"\") = %d rows, want >= 2 (unfiltered)", len(all))
		}
	})
}
