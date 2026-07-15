package pathcorrelation

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestSQLRunLookup_HostSpecificBeatsEnvironmentWide(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()

		// Two agents: one is the host we'll query for, one is a different host.
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			VALUES ('pc-test-agent-target', 'FILE01', '10.0.0.1', 'Windows Server 2022', 'idle', 'active', NOW())`)
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			VALUES ('pc-test-agent-other', 'WS02', '10.0.0.2', 'Windows 11', 'idle', 'active', NOW())`)

		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, started_at)
			VALUES ('pc-test-run-target', 'sc1', 'Test Run', 'pc-test-agent-target', 'completed', NOW())`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, started_at)
			VALUES ('pc-test-run-other', 'sc1', 'Test Run', 'pc-test-agent-other', 'completed', NOW())`)

		olderTime := time.Now().Add(-2 * time.Hour)
		newerTime := time.Now()
		mustExec(t, pool, `INSERT INTO verification_history
			(id, run_id, expectation_id, profile_name, profile_version, technique_id, domain, provider,
			 result, workflow_state, verification_source, note, alert_id, verified_by, verified_at, active)
			VALUES ('pc-test-vh-other', 'pc-test-run-other', 'exp1', 'p', 1, 'T1021.002', 'endpoint', 'test-provider',
			 'Detected', 'Approved', 'automatic', '', 'alert-other', 'tester', $1, true)`, olderTime)
		mustExec(t, pool, `INSERT INTO verification_history
			(id, run_id, expectation_id, profile_name, profile_version, technique_id, domain, provider,
			 result, workflow_state, verification_source, note, alert_id, verified_by, verified_at, active)
			VALUES ('pc-test-vh-target', 'pc-test-run-target', 'exp1', 'p', 1, 'T1021.002', 'endpoint', 'test-provider',
			 'Detected', 'Approved', 'automatic', '', 'alert-target', 'tester', $1, true)`, newerTime)

		lookup := NewSQLRunLookup(pool)

		// Host-specific match must win even though it is not the newest overall
		// row for this technique.
		res, found, err := lookup.VerifiedDetection(ctx, "T1021.002", "FILE01")
		if err != nil {
			t.Fatalf("VerifiedDetection: %v", err)
		}
		if !found {
			t.Fatal("expected a match")
		}
		if res.Confidence != ConfidenceHost {
			t.Fatalf("confidence = %q, want host", res.Confidence)
		}
		if res.Evidence.RunID != "pc-test-run-target" {
			t.Fatalf("runId = %q, want pc-test-run-target", res.Evidence.RunID)
		}

		// A host with no direct history falls back to environment-wide, most
		// recent overall.
		res, found, err = lookup.VerifiedDetection(ctx, "T1021.002", "UNRELATEDHOST")
		if err != nil {
			t.Fatalf("VerifiedDetection: %v", err)
		}
		if !found {
			t.Fatal("expected an environment-wide fallback match")
		}
		if res.Confidence != ConfidenceEnvironment {
			t.Fatalf("confidence = %q, want environment", res.Confidence)
		}
		if res.Evidence.RunID != "pc-test-run-target" {
			t.Fatalf("environment fallback should pick the most recent row (pc-test-run-target), got %q", res.Evidence.RunID)
		}

		// A technique with no history at all anywhere.
		_, found, err = lookup.VerifiedDetection(ctx, "T9999.999", "FILE01")
		if err != nil {
			t.Fatalf("VerifiedDetection: %v", err)
		}
		if found {
			t.Fatal("expected no match for an untested technique")
		}
	})
}
