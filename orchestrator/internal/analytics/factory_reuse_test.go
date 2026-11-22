package analytics

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedComponent(t *testing.T, pool *pgxpool.Pool, title, originVersionID string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO content_components (kind, technique_id, title, origin_content_version_id, step_snapshot, promoted_by)
		VALUES ('internal', 'T1059', $1, $2, '{}', 'user:t') RETURNING id`, title, originVersionID).Scan(&id); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	return id
}

func useComponent(t *testing.T, pool *pgxpool.Pool, versionID, componentID string, order int) {
	t.Helper()
	mustExec(t, pool, `INSERT INTO content_version_components (content_version_id, component_id, step_order) VALUES ($1,$2,$3)`,
		versionID, componentID, order)
}

func TestFactoryReuse_ComposedShareAndDistinctReusedComponents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedThreatWithActor(t, pool, "ru-threat", "Actor RU")
		auto := [][2]string{{"PUBLISHED_LOCAL", "user:pub"}}

		// Freshly generated (generated_for link, no components).
		gen := seedPublishedWithEvents(t, pool, "ru-gen", "generator:connector", auto)
		linkGeneratedFor(t, pool, gen, "ru-threat")
		// Component X was promoted from the generated version.
		x := seedComponent(t, pool, "X", gen)

		// Two composed versions share X; the second also has Y, whose origin is itself.
		c1 := seedPublishedWithEvents(t, pool, "ru-c1", "composer:admin", auto)
		c2 := seedPublishedWithEvents(t, pool, "ru-c2", "composer:admin", auto)
		y := seedComponent(t, pool, "Y", c2)
		useComponent(t, pool, c1, x, 0)
		useComponent(t, pool, c2, x, 0)
		useComponent(t, pool, c2, y, 1)

		// A human-created version using X is not factory output and must not count.
		h := seedPublishedWithEvents(t, pool, "ru-human", "user:alice", auto)
		useComponent(t, pool, h, x, 0)

		got, err := factoryReuse(context.Background(), pool, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("factoryReuse: %v", err)
		}
		if *got.FactoryVersions.Value != 3 {
			t.Fatalf("FactoryVersions = %v, want 3 (gen + 2 composed; human excluded)", *got.FactoryVersions.Value)
		}
		if *got.ComposedFromLibrary.Value != 2 {
			t.Fatalf("ComposedFromLibrary = %v, want 2", *got.ComposedFromLibrary.Value)
		}
		if got.ReuseRate.State != DataMeasured || *got.ReuseRate.Value != 2.0/3.0 {
			t.Fatalf("ReuseRate = %+v, want 2/3", got.ReuseRate)
		}
		if *got.LibraryComponentsReused.Value != 1 {
			t.Fatalf("LibraryComponentsReused = %v, want 1 (X once; Y is used only by its own origin)", *got.LibraryComponentsReused.Value)
		}
	})
}

func TestFactoryReuse_NoDataWhenNoFactoryContentCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := factoryReuse(context.Background(), pool, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("factoryReuse: %v", err)
		}
		if got.ReuseRate.State != DataNoData {
			t.Fatalf("ReuseRate = %+v, want NO_DATA, not 0%%", got.ReuseRate)
		}
	})
}
