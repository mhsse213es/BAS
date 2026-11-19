package tcv

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func countEventsByVID(t *testing.T, pool *pgxpool.Pool, eventType, cvid string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tcf_pipeline_events WHERE event_type=$1 AND content_version_id=$2`,
		eventType, cvid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Acceptance test 8: a content_generation_attempts row with outcome='created'
// and no ledger event is healed by reconciliation into a content_created
// event carrying the source completed_at, and a second pass adds no duplicate.
func TestReconcile_EmitsMissingContentCreated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		started := time.Now().Add(-2 * time.Hour).Truncate(time.Microsecond)
		completed := started.Add(5 * time.Second)
		if _, err := pool.Exec(ctx, `INSERT INTO content_generation_attempts
			(id, cycle_id, threat_id, content_version_id, outcome, reason_code, generator_version, started_at, completed_at)
			VALUES ('cga-recon-1','cycle-1','thr-recon','cv-recon','created','ok','1',$1,$2)`, started, completed); err != nil {
			t.Fatal(err)
		}

		if n := countEventsByVID(t, pool, "content_created", "cv-recon"); n != 0 {
			t.Fatalf("pre-reconcile content_created=%d, want 0", n)
		}

		if err := ReconcilePipelineEvents(ctx, pool, time.Time{}); err != nil {
			t.Fatal(err)
		}

		var evAt time.Time
		if err := pool.QueryRow(ctx,
			`SELECT event_time FROM tcf_pipeline_events WHERE event_type='content_created' AND content_version_id='cv-recon'`).
			Scan(&evAt); err != nil {
			t.Fatalf("content_created not emitted by reconcile: %v", err)
		}
		if !evAt.Equal(completed) {
			t.Fatalf("content_created event_time=%s, want source completed_at %s", evAt, completed)
		}

		// Second pass is idempotent.
		if err := ReconcilePipelineEvents(ctx, pool, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if n := countEventsByVID(t, pool, "content_created", "cv-recon"); n != 1 {
			t.Fatalf("after 2nd reconcile content_created=%d, want 1 (idempotent)", n)
		}
	})
}

// Review Focus / §10: reconciliation never fabricates threat_eligible, which
// is a generator-internal decision unrecoverable from any source row.
func TestReconcile_NeverEmitsEligible(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO content_generation_attempts
			(id, cycle_id, threat_id, content_version_id, outcome, reason_code, generator_version, started_at)
			VALUES ('cga-elig-1','cycle-e','thr-elig','cv-elig','created','ok','1', now())`); err != nil {
			t.Fatal(err)
		}

		if err := ReconcilePipelineEvents(ctx, pool, time.Time{}); err != nil {
			t.Fatal(err)
		}

		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM tcf_pipeline_events WHERE event_type='threat_eligible' AND threat_id='thr-elig'`).
			Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("reconcile emitted %d threat_eligible, want 0 (unreconstructable)", n)
		}
	})
}

// Finding 4: the periodic heal is bounded by `since`; rows older than the
// window are skipped, while the boot backfill (since=zero) still heals them.
func TestReconcile_RespectsSinceWindow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		old := time.Now().Add(-48 * time.Hour).Truncate(time.Microsecond)
		if _, err := pool.Exec(ctx, `INSERT INTO content_generation_attempts
			(id, cycle_id, threat_id, content_version_id, outcome, reason_code, generator_version, started_at, completed_at)
			VALUES ('cga-win','c','thr-win','cv-win','created','ok','1',$1,$1)`, old); err != nil {
			t.Fatal(err)
		}
		count := func() int {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE event_type='content_created' AND content_version_id='cv-win'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}

		// A recent window excludes the 48h-old row.
		if err := ReconcilePipelineEvents(ctx, pool, time.Now().Add(-1*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if n := count(); n != 0 {
			t.Fatalf("row older than since must not be reconciled, got %d", n)
		}
		// The full boot backfill heals it.
		if err := ReconcilePipelineEvents(ctx, pool, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if n := count(); n != 1 {
			t.Fatalf("full backfill must heal the old row, got %d", n)
		}
	})
}
