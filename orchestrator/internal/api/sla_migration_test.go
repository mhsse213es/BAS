package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSLAPolicySeed_FourDefaultRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		want := map[string]int{"Critical": 24, "High": 72, "Medium": 168, "Low": 720}
		for severity, hours := range want {
			var got int
			if err := pool.QueryRow(context.Background(),
				`SELECT duration_hours FROM sla_policy WHERE severity=$1`, severity,
			).Scan(&got); err != nil {
				t.Fatalf("query %s: %v", severity, err)
			}
			if got != hours {
				t.Errorf("sla_policy[%s].duration_hours = %d, want %d", severity, got, hours)
			}
		}
	})
}

func TestSLAMigration_BackfillsExistingOpenFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('backfill-agent', 'BACKFILL-AGENT')`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-backfill-1', 'backfill-agent', 'windows-firewall-enabled', 'security-configuration', 'Windows Firewall disabled', 'High', 'open', NOW(), NOW(), NOW())`)

		// The backfill is a one-time repair inside the frozen pre-H1 chain; it
		// runs when migrate adopts a pre-H1 install (internal/db/legacy).
		if err := legacy.EnsureSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureSchema (2nd run): %v", err)
		}

		var status string
		var startedAt, deadlineAt time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, started_at, deadline_at FROM finding_slas WHERE posture_finding_id='pf-backfill-1'`,
		).Scan(&status, &startedAt, &deadlineAt); err != nil {
			t.Fatalf("expected a backfilled finding_slas row: %v", err)
		}
		if status != "active" {
			t.Errorf("status = %q, want active", status)
		}
		gotHours := deadlineAt.Sub(startedAt).Hours()
		if gotHours < 71.9 || gotHours > 72.1 {
			t.Errorf("deadline - started = %.2fh, want ~72h (High severity policy)", gotHours)
		}

		// Idempotency: a 3rd EnsureSchema run must not create a 2nd row for
		// the same posture_finding_id.
		if err := legacy.EnsureSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureSchema (3rd run): %v", err)
		}
		var n int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM finding_slas WHERE posture_finding_id='pf-backfill-1'`,
		).Scan(&n); err != nil || n != 1 {
			t.Fatalf("finding_slas rows for pf-backfill-1 = %d (err=%v), want exactly 1", n, err)
		}
	})
}
