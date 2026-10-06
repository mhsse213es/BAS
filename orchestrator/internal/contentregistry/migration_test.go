package contentregistry

import (
	"context"
	"sync"
	"testing"
	"time"

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
		r.NoteRefusal("tampered.yaml", "bad", "builtin", "signature invalid")
		// Custom/intel refusals are not builtin refusals (final-review M3).
		r.NoteRefusal("custom/dup.yaml", "dup", "custom", "duplicate id; higher-precedence file wins")
		r.NoteRefusal("intel/x.yaml", "x", "intel", ErrSourceCollision.Error())
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

		// A custom file first seen after the marker is DRAFT and not grandfathered.
		in("custom", "id: c2\nname: C2\nlocal_check: true\n")
		vs, err := r.ListVersions(ctx, "c2")
		if err != nil || len(vs) != 1 || vs[0].Lifecycle != LifecycleDraft {
			t.Fatalf("post-marker custom file must be DRAFT: %+v err=%v", vs, err)
		}
		inv3, first3, err := r.CompleteMigration(ctx)
		if err != nil || first3 {
			t.Fatalf("third run: first=%v err=%v", first3, err)
		}
		for _, id := range inv3.CustomGrandfathered {
			if id == "c2" {
				t.Fatalf("c2 must not be grandfathered: %+v", inv3.CustomGrandfathered)
			}
		}
	})
}

// The polled blocked-schedule check must fail closed without writing audit rows.
func TestBlockedSchedulesWritesNoAudit(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, testutil.DevVerifier()) // dev build: VENDOR_SIGNED cannot be verified, so denied
		signedPublished(t, r, signer, "vs1", "V")
		if _, err := pool.Exec(ctx, `INSERT INTO job_schedules (type, payload, agent_ids, day_of_week, time_of_day) VALUES
			('scheduled_assessment', '{"scenarioId":"vs1"}', '[]', 1, '09:00'),
			('scheduled_assessment', '{"scenarioId":"vs1"}', '[]', 2, '09:00')`); err != nil {
			t.Fatal(err)
		}
		count := func() int {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := count()
		for i := 0; i < 2; i++ {
			blocked, err := r.BlockedSchedules(ctx)
			if err != nil || len(blocked) != 2 {
				t.Fatalf("denied vendor-signed content must block both schedules: %+v err=%v", blocked, err)
			}
		}
		if after := count(); after != before {
			t.Fatalf("audit_logs rows %d -> %d; BlockedSchedules must not audit", before, after)
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
		var stamps []time.Time
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				inv, first, err := r.CompleteMigration(ctx)
				if err != nil {
					t.Errorf("CompleteMigration: %v", err)
					return
				}
				mu.Lock()
				stamps = append(stamps, inv.MigratedAt)
				if first {
					wins++
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("firstTime winners = %d, want 1", wins)
		}
		if len(stamps) != 6 {
			t.Fatalf("callers returned %d results", len(stamps))
		}
		for _, ts := range stamps {
			if ts.IsZero() || !ts.Equal(stamps[0]) {
				t.Fatalf("callers must return the same stored inventory: %v vs %v", ts, stamps[0])
			}
		}
	})
}
