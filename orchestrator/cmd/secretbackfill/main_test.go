package main

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB = testutil.MustSharedTestDB()

const leakedValue = "Hunter2!SecretXYZ123"

func seedBackfillRun(t *testing.T, pool *pgxpool.Pool, id, results string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname) VALUES ('agent-bf', 'HOST-BF') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results)
		VALUES ($1, 'sc-bf', 'agent-bf', 'backfill run', 'completed', $2::jsonb)`, id, results); err != nil {
		t.Fatalf("seed run %s: %v", id, err)
	}
}

func storedResults(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(),
		`SELECT results::text FROM scenario_runs WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("read run %s: %v", id, err)
	}
	return s
}

func TestBackfillRuns_DryRunWritesNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dirty := `[{"technique":{"id":"T1059"},"result":"fail","rawOutput":"password=` + leakedValue + `"}]`
		seedBackfillRun(t, pool, "run-bf-dry", dirty)

		changed, err := backfillRuns(context.Background(), pool, false)
		if err != nil {
			t.Fatalf("backfillRuns dry run: %v", err)
		}
		if len(changed) != 1 || changed[0] != "run-bf-dry" {
			t.Errorf("dry run reported %v, want [run-bf-dry]", changed)
		}
		if !strings.Contains(storedResults(t, pool, "run-bf-dry"), leakedValue) {
			t.Error("dry run wrote to the database; the stored secret must still be there")
		}
	})
}

func TestBackfillRuns_ApplyScrubsAndIsIdempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dirty := `[{"technique":{"id":"T1059"},"result":"fail","rawOutput":"password=` + leakedValue + `"}]`
		clean := `[{"technique":{"id":"T1082"},"result":"pass","rawOutput":"ordinary output"}]`
		seedBackfillRun(t, pool, "run-bf-apply", dirty)
		seedBackfillRun(t, pool, "run-bf-clean", clean)

		changed, err := backfillRuns(context.Background(), pool, true)
		if err != nil {
			t.Fatalf("backfillRuns apply: %v", err)
		}
		if len(changed) != 1 || changed[0] != "run-bf-apply" {
			t.Errorf("apply reported %v, want [run-bf-apply]", changed)
		}
		if strings.Contains(storedResults(t, pool, "run-bf-apply"), leakedValue) {
			t.Error("apply left the stored secret in place")
		}
		if !strings.Contains(storedResults(t, pool, "run-bf-clean"), "ordinary output") {
			t.Error("a clean row was altered")
		}

		again, err := backfillRuns(context.Background(), pool, true)
		if err != nil {
			t.Fatalf("second apply: %v", err)
		}
		if len(again) != 0 {
			t.Errorf("second apply changed %v; a scrubbed database must be a no-op", again)
		}
	})
}

func TestBackfillIOCs_CollisionSkippedNotForced(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		dirtyValue := "tool password=" + leakedValue
		cleanValue := "tool password=[withheld: secret]"
		for _, v := range []string{dirtyValue, cleanValue} {
			if _, err := pool.Exec(ctx,
				`INSERT INTO iocs (type, value, source) VALUES ('command_line', $1, 'test')`, v); err != nil {
				t.Fatalf("seed ioc: %v", err)
			}
		}

		changed, collisions, err := backfillIOCs(ctx, pool, true)
		if err != nil {
			t.Fatalf("backfillIOCs: %v", err)
		}
		if changed != 1 {
			t.Errorf("changed = %d, want 1", changed)
		}
		if len(collisions) != 1 {
			t.Errorf("collisions = %v, want the one colliding IOC reported", collisions)
		}
		var still int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM iocs WHERE value LIKE '%' || $1 || '%'`, leakedValue).Scan(&still); err != nil {
			t.Fatalf("count: %v", err)
		}
		if still != 1 {
			t.Errorf("the colliding IOC must stay for a person to resolve; found %d rows with the secret", still)
		}
	})
}
