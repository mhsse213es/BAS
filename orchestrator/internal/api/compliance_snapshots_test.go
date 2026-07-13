package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRefreshComplianceSnapshots_NilMapper_NoOp pins the documented no-op
// guard: refreshComplianceSnapshots must not touch the DB when the compliance
// mapper isn't loaded (it's fired as a fire-and-forget goroutine after every
// run completion, so it must never panic on a nil dependency).
func TestRefreshComplianceSnapshots_NilMapper_NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rcs-nilmapper-run", "agent-rcs-nilmapper", reportRunOpts{})
		// No WithCompliance — complianceMapper stays nil.
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.refreshComplianceSnapshots(context.Background(), "agent-rcs-nilmapper")

		var n int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM compliance_snapshots WHERE agent_id = $1`, "agent-rcs-nilmapper",
		).Scan(&n); err != nil {
			t.Fatalf("query compliance_snapshots: %v", err)
		}
		if n != 0 {
			t.Fatalf("nil mapper should be a no-op, found %d snapshot rows", n)
		}
	})
}

// TestRefreshComplianceSnapshots_PersistsPerFramework pins the core contract:
// one compliance_snapshots row per bundled framework, with the SEBI_CSCRF row
// reflecting real scored data from canonicalResults (not a zero-state stub).
func TestRefreshComplianceSnapshots_PersistsPerFramework(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rcs-persist-run", "agent-rcs-persist", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		h.refreshComplianceSnapshots(context.Background(), "agent-rcs-persist")

		var n int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM compliance_snapshots WHERE agent_id = $1`, "agent-rcs-persist",
		).Scan(&n); err != nil {
			t.Fatalf("query compliance_snapshots: %v", err)
		}
		if n != 7 {
			t.Fatalf("expected one snapshot row per bundled framework, got %d", n)
		}

		var runCount, testedControls, failingControls int
		if err := pool.QueryRow(context.Background(),
			`SELECT run_count, tested_controls, failing_controls FROM compliance_snapshots
			  WHERE agent_id = $1 AND framework_id = 'SEBI_CSCRF'`, "agent-rcs-persist",
		).Scan(&runCount, &testedControls, &failingControls); err != nil {
			t.Fatalf("query SEBI_CSCRF snapshot: %v", err)
		}
		if runCount != 1 {
			t.Errorf("run_count = %d, want 1", runCount)
		}
		if testedControls == 0 {
			t.Error("tested_controls = 0, want > 0 (canonicalResults maps into SEBI_CSCRF controls)")
		}
		if failingControls == 0 {
			t.Error("failing_controls = 0, want > 0 (canonicalResults has FAIL techniques mapped into SEBI_CSCRF)")
		}
	})
}

// TestRefreshComplianceSnapshots_Idempotent pins the ON CONFLICT upsert:
// running it twice for the same (agent, framework) must overwrite the
// existing row, not insert a duplicate, and must reflect the latest input
// (run_count grows once a second run is seeded).
func TestRefreshComplianceSnapshots_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rcs-idem-run-1", "agent-rcs-idem", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		h.refreshComplianceSnapshots(context.Background(), "agent-rcs-idem")

		seedReportableRun(t, pool, "rcs-idem-run-2", "agent-rcs-idem", reportRunOpts{})
		h.refreshComplianceSnapshots(context.Background(), "agent-rcs-idem")

		var n, runCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM compliance_snapshots WHERE agent_id = $1 AND framework_id = 'SEBI_CSCRF'`,
			"agent-rcs-idem",
		).Scan(&n); err != nil {
			t.Fatalf("query row count: %v", err)
		}
		if n != 1 {
			t.Fatalf("second refresh should overwrite via ON CONFLICT, found %d rows", n)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT run_count FROM compliance_snapshots WHERE agent_id = $1 AND framework_id = 'SEBI_CSCRF'`,
			"agent-rcs-idem",
		).Scan(&runCount); err != nil {
			t.Fatalf("query run_count: %v", err)
		}
		if runCount != 2 {
			t.Fatalf("run_count = %d, want 2 (reflects the second refresh's 2 completed runs)", runCount)
		}
	})
}
