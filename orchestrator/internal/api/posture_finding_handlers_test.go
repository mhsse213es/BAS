package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPostureTestHandler builds a Handler with a real Taxonomy loaded --
// upsertPostureFindingsForRun no-ops when h.endpointRiskTaxonomy is nil.
func newPostureTestHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	tx, err := endpointrisk.NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	h.endpointRiskTaxonomy = tx
	return h
}

// seedPostureCheckRun seeds an agent (idempotent) and a scenario_runs row
// carrying one posture-check result for check_id="windows-firewall-enabled"
// (a real Security Configuration entry in postureCheckFindingText). Mirrors
// the raw-JSON seeding style already used in endpointrisk_aggregations_test.go
// and endpointrisk_handlers_test.go, rather than marshaling a
// models.SimulationResult Go struct.
func seedPostureCheckRun(t *testing.T, pool *pgxpool.Pool, runID, agentID, result string, at time.Time) {
	t.Helper()
	mustExecAPI(t, pool,
		`INSERT INTO agents (agent_id, hostname) VALUES ($1, $2) ON CONFLICT (agent_id) DO NOTHING`,
		agentID, "host-"+agentID)
	mustExecAPI(t, pool,
		`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, completed_at)
		 VALUES ($1, 'pf-scenario', 'PF Run', $2, 'completed', $3::jsonb, $4, $4)`,
		runID, agentID,
		`[{"checkId":"windows-firewall-enabled","result":"`+result+`","executedAt":"`+at.UTC().Format(time.RFC3339)+`"}]`,
		at)
}

func TestUpsertPostureFindingsForRun_FirstFailCreatesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		now := time.Now()
		seedPostureCheckRun(t, pool, "pf-fail-1", "agent-pf-fail", "fail", now)

		h.upsertPostureFindingsForRun(context.Background(), "pf-fail-1")

		var status string
		var occ int
		err := pool.QueryRow(context.Background(),
			`SELECT status, occurrence_count FROM posture_findings WHERE agent_id='agent-pf-fail' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &occ)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" || occ != 1 {
			t.Errorf("status=%q occurrence_count=%d, want open/1", status, occ)
		}
	})
}

func TestUpsertPostureFindingsForRun_SecondFailRecurs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		seedPostureCheckRun(t, pool, "pf-recur-1", "agent-pf-recur", "fail", t1)
		seedPostureCheckRun(t, pool, "pf-recur-2", "agent-pf-recur", "fail", t2)

		h.upsertPostureFindingsForRun(context.Background(), "pf-recur-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-recur-2")

		var status string
		var occ, rowCount int
		err := pool.QueryRow(context.Background(),
			`SELECT status, occurrence_count FROM posture_findings WHERE agent_id='agent-pf-recur' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &occ)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" || occ != 2 {
			t.Errorf("status=%q occurrence_count=%d, want open/2 (same row)", status, occ)
		}
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM posture_findings WHERE agent_id='agent-pf-recur'`).Scan(&rowCount)
		if rowCount != 1 {
			t.Errorf("rowCount=%d, want exactly 1 row (counters, not one row per occurrence)", rowCount)
		}
	})
}

func TestUpsertPostureFindingsForRun_PassHeals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		seedPostureCheckRun(t, pool, "pf-heal-1", "agent-pf-heal", "fail", t1)
		seedPostureCheckRun(t, pool, "pf-heal-2", "agent-pf-heal", "pass", t2)

		h.upsertPostureFindingsForRun(context.Background(), "pf-heal-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-heal-2")

		var status, reason string
		var resolvedAt *time.Time
		err := pool.QueryRow(context.Background(),
			`SELECT status, resolved_at, resolved_reason FROM posture_findings WHERE agent_id='agent-pf-heal' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &resolvedAt, &reason)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "remediated" || resolvedAt == nil || reason != "re-validated pass" {
			t.Errorf("status=%q resolvedAt=%v reason=%q, want remediated/non-nil/\"re-validated pass\"", status, resolvedAt, reason)
		}
	})
}

func TestUpsertPostureFindingsForRun_ReopenAfterHeal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		t3 := t1.Add(2 * time.Hour)
		seedPostureCheckRun(t, pool, "pf-reopen-1", "agent-pf-reopen", "fail", t1)
		seedPostureCheckRun(t, pool, "pf-reopen-2", "agent-pf-reopen", "pass", t2)
		seedPostureCheckRun(t, pool, "pf-reopen-3", "agent-pf-reopen", "fail", t3)

		h.upsertPostureFindingsForRun(context.Background(), "pf-reopen-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-reopen-2")
		h.upsertPostureFindingsForRun(context.Background(), "pf-reopen-3")

		var status string
		var resolvedAt *time.Time
		var reopened int
		err := pool.QueryRow(context.Background(),
			`SELECT status, resolved_at, reopened_count FROM posture_findings WHERE agent_id='agent-pf-reopen' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &resolvedAt, &reopened)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" || resolvedAt != nil || reopened != 1 {
			t.Errorf("status=%q resolvedAt=%v reopened_count=%d, want open/nil/1", status, resolvedAt, reopened)
		}
	})
}

func TestUpsertPostureFindingsForRun_OutOfOrderRunIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		newer := time.Now()
		older := newer.Add(-time.Hour)
		seedPostureCheckRun(t, pool, "pf-ooo-1", "agent-pf-ooo", "fail", newer)
		seedPostureCheckRun(t, pool, "pf-ooo-2", "agent-pf-ooo", "pass", older)

		h.upsertPostureFindingsForRun(context.Background(), "pf-ooo-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-ooo-2")

		var status string
		err := pool.QueryRow(context.Background(),
			`SELECT status FROM posture_findings WHERE agent_id='agent-pf-ooo' AND check_id='windows-firewall-enabled'`,
		).Scan(&status)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" {
			t.Errorf("status=%q, want open (the older passing run must not heal a newer failure)", status)
		}
	})
}

func TestUpsertPostureFindingsForRun_OutOfScopeCategoryNeverCreatesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		now := time.Now()
		mustExecAPI(t, pool,
			`INSERT INTO agents (agent_id, hostname) VALUES ('agent-pf-oos', 'host-agent-pf-oos') ON CONFLICT (agent_id) DO NOTHING`)
		mustExecAPI(t, pool,
			`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, completed_at)
			 VALUES ('pf-oos-1', 'pf-scenario', 'PF Run', 'agent-pf-oos', 'completed', $1::jsonb, $2, $2)`,
			`[{"checkId":"windows-installed-software","result":"fail","executedAt":"`+now.UTC().Format(time.RFC3339)+`"}]`,
			now)

		h.upsertPostureFindingsForRun(context.Background(), "pf-oos-1")

		var count int
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM posture_findings WHERE agent_id='agent-pf-oos'`).Scan(&count)
		if count != 0 {
			t.Errorf("count=%d, want 0 (windows-installed-software is Application Risk, out of scope)", count)
		}
	})
}
