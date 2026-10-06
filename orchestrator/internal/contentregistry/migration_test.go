package contentregistry

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

func TestMigrationIdempotentWithInventory(t *testing.T) { // A14
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		in := func(src, body string) {
			t.Helper()
			if _, err := r.Intake(ctx, scenario.IntakeFile{Path: src + "/f.yaml", Source: src, Artifact: []byte(body)}); err != nil {
				t.Fatalf("intake %s: %v", src, err)
			}
		}
		in("builtin", "id: b1\nname: B\nlocal_check: true\n")
		in("custom", "id: c1\nname: C\nlocal_check: true\n")
		in("intel", "id: intel-1\nname: I\nart_techniques: [T1082]\n")
		r.NoteRefusal("tampered.yaml", "bad", "signature invalid")
		if _, err := pool.Exec(ctx, `INSERT INTO job_schedules (type, payload, agent_ids, day_of_week, time_of_day)
			VALUES ('scheduled_assessment', '{"scenarioId":"intel-1"}', '[]', 1, '09:00')`); err != nil {
			t.Fatalf("seed schedule: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO campaigns (id, name, scenario_id) VALUES ('camp1', 'Camp', 'intel-1')`); err != nil {
			t.Fatalf("seed campaign: %v", err)
		}

		inv, first, err := r.CompleteMigration(ctx)
		if err != nil || !first {
			t.Fatalf("first: %v %v", first, err)
		}
		if len(inv.IntelDrafted) != 1 || inv.IntelDrafted[0] != "intel-1" ||
			len(inv.CustomGrandfathered) != 1 || inv.CustomGrandfathered[0] != "c1" ||
			len(inv.AffectedSchedules) != 1 || len(inv.AffectedCampaigns) != 1 || len(inv.BuiltinRefused) != 1 {
			t.Fatalf("inventory: %+v", inv)
		}
		var events int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_events WHERE actor = $1 AND reason = $2`, ActorMigration, MigrationReason).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if events != 1 {
			t.Fatalf("grandfather events = %d", events)
		}

		before, err := r.ListVersions(ctx, "c1")
		if err != nil {
			t.Fatal(err)
		}
		in("custom", "id: c1\nname: C\nlocal_check: true\n") // re-run intake after migration: no-op
		inv2, first2, err := r.CompleteMigration(ctx)
		after, lerr := r.ListVersions(ctx, "c1")
		if lerr != nil {
			t.Fatal(lerr)
		}
		if err != nil || first2 || len(after) != len(before) || !inv2.MigratedAt.Equal(inv.MigratedAt) {
			t.Fatalf("second run must be a no-op: first=%v err=%v versions %d->%d", first2, err, len(before), len(after))
		}
		blocked, err := r.BlockedSchedules(ctx)
		if err != nil || len(blocked) != 1 {
			t.Fatalf("blocked schedules = %d err=%v", len(blocked), err)
		}
	})
}

// BlockedSchedules is live: it tracks the gate rather than any stored
// inventory. An unregistered scenario blocks, and so does one whose only
// executable version is retired.
func TestBlockedSchedulesIsLive(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := r.Intake(ctx, scenario.IntakeFile{Path: "builtin/f.yaml", Source: "builtin", Artifact: []byte("id: ok1\nname: B\nlocal_check: true\n")}); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO job_schedules (type, payload, agent_ids, day_of_week, time_of_day) VALUES
			('scheduled_assessment', '{"scenarioId":"ok1"}', '[]', 1, '09:00'),
			('scheduled_assessment', '{"scenarioId":"ghost"}', '[]', 1, '09:00')`); err != nil {
			t.Fatal(err)
		}
		blocked, err := r.BlockedSchedules(ctx)
		if err != nil || len(blocked) != 1 || blocked[0].ScenarioID != "ghost" {
			t.Fatalf("blocked = %+v err=%v", blocked, err)
		}
		// Retire the only version of ok1: it must now block too.
		if _, err := pool.Exec(ctx, `UPDATE content_versions SET lifecycle = 'RETIRED' WHERE content_id = 'ok1'`); err != nil {
			t.Fatalf("retire: %v", err)
		}
		blocked, err = r.BlockedSchedules(ctx)
		if err != nil || len(blocked) != 2 {
			t.Fatalf("after retire blocked = %+v err=%v", blocked, err)
		}
	})
}

func TestCompleteMigrationConcurrentSingleWinner(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		var mu sync.Mutex
		wins := 0
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, first, err := r.CompleteMigration(ctx)
				if err != nil {
					t.Errorf("CompleteMigration: %v", err)
					return
				}
				if first {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("firstTime winners = %d, want 1", wins)
		}
	})
}
