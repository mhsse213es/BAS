package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestListAgentPostureFindings_EmptyReturnsEmptyList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('agent-pf-empty', 'host-agent-pf-empty')`)

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "agent-pf-empty")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %d findings, want 0", len(got))
		}
	})
}

func TestListAgentPostureFindings_ReturnsOpenByDefaultAndAllOnFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		seedPostureCheckRun(t, pool, "pf-list-1", "agent-pf-list", "fail", t1)
		h.upsertPostureFindingsForRun(context.Background(), "pf-list-1")
		seedPostureCheckRun(t, pool, "pf-list-2", "agent-pf-list", "pass", t2)
		h.upsertPostureFindingsForRun(context.Background(), "pf-list-2")
		// finding is now status=remediated

		reqOpen := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "agent-pf-list")
		wOpen := httptest.NewRecorder()
		h.ListAgentPostureFindings(wOpen, reqOpen)
		var openOnly []map[string]any
		if err := json.Unmarshal(wOpen.Body.Bytes(), &openOnly); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(openOnly) != 0 {
			t.Errorf("default (open-only) got %d, want 0 (finding is remediated)", len(openOnly))
		}

		reqAll := withURLParam(httptest.NewRequest(http.MethodGet, "/x?status=all", nil), "agentId", "agent-pf-list")
		wAll := httptest.NewRecorder()
		h.ListAgentPostureFindings(wAll, reqAll)
		var all []map[string]any
		if err := json.Unmarshal(wAll.Body.Bytes(), &all); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(all) != 1 {
			t.Fatalf("?status=all got %d, want 1", len(all))
		}
		if all[0]["checkId"] != "windows-firewall-enabled" {
			t.Errorf("checkId=%v, want windows-firewall-enabled", all[0]["checkId"])
		}
		if all[0]["status"] != "remediated" {
			t.Errorf("status=%v, want remediated", all[0]["status"])
		}
	})
}

func TestGetPostureFinding_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nonexistent-id")
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("status=%d, want 404", w.Code)
		}
	})
}

func TestGetPostureFinding_ReturnsFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "pf-get-1", "agent-pf-get", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "pf-get-1")

		var id string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='agent-pf-get' AND check_id='windows-firewall-enabled'`).Scan(&id)

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", id)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", w.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["checkId"] != "windows-firewall-enabled" {
			t.Errorf("checkId=%v, want windows-firewall-enabled", got["checkId"])
		}
	})
}

func TestUpsertPostureFindingsForRun_PersistsPerCheckSeverity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		// seedPostureCheckRun hardcodes check_id="windows-firewall-enabled" --
		// its severity per postureCheckFindingText is "High".
		seedPostureCheckRun(t, pool, "sev-run-high", "sev-agent", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sev-run-high")

		var severity string
		if err := pool.QueryRow(context.Background(),
			`SELECT severity FROM posture_findings WHERE agent_id='sev-agent' AND check_id='windows-firewall-enabled'`,
		).Scan(&severity); err != nil {
			t.Fatalf("query: %v", err)
		}
		if severity != "High" {
			t.Fatalf("severity = %q, want High (was defaulting to Medium before this fix)", severity)
		}
	})
}

func TestApplyPostureFinding_CreatedStartsSLAClock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		// windows-firewall-enabled is the only check_id seedPostureCheckRun
		// seeds (it hardcodes it) -- severity "High" per postureCheckFindingText.
		seedPostureCheckRun(t, pool, "sla-run-1", "sla-a1", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-1")

		var pfID, status, severityAtStart string
		if err := pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='sla-a1' AND check_id='windows-firewall-enabled'`,
		).Scan(&pfID); err != nil {
			t.Fatalf("posture_findings query: %v", err)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT status, severity_at_start FROM finding_slas WHERE posture_finding_id=$1`, pfID,
		).Scan(&status, &severityAtStart); err != nil {
			t.Fatalf("expected a finding_slas row: %v", err)
		}
		if status != "active" || severityAtStart != "High" {
			t.Errorf("status=%q severityAtStart=%q, want active/High", status, severityAtStart)
		}
	})
}

func TestApplyPostureFinding_HealedResolvesActiveSLA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		seedPostureCheckRun(t, pool, "sla-run-2a", "sla-a2", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-2a")
		seedPostureCheckRun(t, pool, "sla-run-2b", "sla-a2", "pass", time.Now().Add(time.Hour))
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-2b")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='sla-a2' AND check_id='windows-firewall-enabled'`,
		).Scan(&pfID)

		var status string
		var resolvedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, resolved_at FROM finding_slas WHERE posture_finding_id=$1`, pfID,
		).Scan(&status, &resolvedAt); err != nil {
			t.Fatalf("query: %v", err)
		}
		if status != "resolved" || resolvedAt == nil {
			t.Errorf("status=%q resolvedAt=%v, want resolved/non-nil", status, resolvedAt)
		}
	})
}

func TestApplyPostureFinding_ReopenedStartsNewSLAEpisode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		seedPostureCheckRun(t, pool, "sla-run-3a", "sla-a3", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-3a")
		seedPostureCheckRun(t, pool, "sla-run-3b", "sla-a3", "pass", time.Now().Add(time.Hour))
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-3b")
		seedPostureCheckRun(t, pool, "sla-run-3c", "sla-a3", "fail", time.Now().Add(2*time.Hour))
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-3c")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='sla-a3' AND check_id='windows-firewall-enabled'`,
		).Scan(&pfID)

		var total, activeCount, resolvedCount int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE posture_finding_id=$1`, pfID).Scan(&total)
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE posture_finding_id=$1 AND status='active'`, pfID).Scan(&activeCount)
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE posture_finding_id=$1 AND status='resolved'`, pfID).Scan(&resolvedCount)
		if total != 2 || activeCount != 1 || resolvedCount != 1 {
			t.Errorf("total=%d active=%d resolved=%d, want 2/1/1 (prior episode resolved, new episode active)", total, activeCount, resolvedCount)
		}
	})
}

func TestListAgentPostureFindings_IncludesSLAFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		seedPostureCheckRun(t, pool, "sla-read-run", "sla-read-1", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-read-run")

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "sla-read-1")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if got[0]["slaStatus"] != "active" {
			t.Errorf("slaStatus = %v, want active", got[0]["slaStatus"])
		}
		if got[0]["slaDeadlineAt"] == nil {
			t.Errorf("slaDeadlineAt missing")
		}
	})
}

func seedRemediationRequest(t *testing.T, pool *pgxpool.Pool, id, agentID, checkID, status string, requestedAt time.Time) {
	t.Helper()
	mustExecAPI(t, pool,
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
		 VALUES ($1, 'test-remediation', $2, $3, 1, $4, 'user-1', 'test', $5)`,
		id, agentID, checkID, status, requestedAt)
}

func TestListAgentPostureFindings_NoRemediationAttempt_LatestRemediationAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-none", "rt-none", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-none")

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "rt-none")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if _, present := got[0]["latestRemediation"]; present {
			t.Errorf("latestRemediation present = %v, want absent", got[0]["latestRemediation"])
		}
	})
}

func TestGetPostureFinding_OneRemediationAttempt_Surfaced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-one", "rt-one", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-one")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='rt-one' AND check_id='windows-firewall-enabled'`).Scan(&pfID)
		seedRemediationRequest(t, pool, "rr-one", "rt-one", "windows-firewall-enabled", "running", time.Now().Add(time.Minute))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		lr, ok := got["latestRemediation"].(map[string]any)
		if !ok {
			t.Fatalf("latestRemediation missing or wrong shape: %v", got["latestRemediation"])
		}
		if lr["id"] != "rr-one" || lr["status"] != "running" || lr["inProgress"] != true {
			t.Errorf("latestRemediation = %+v, want id=rr-one status=running inProgress=true", lr)
		}
	})
}

func TestGetPostureFinding_MultipleAttempts_NewestWins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-multi", "rt-multi", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-multi")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='rt-multi' AND check_id='windows-firewall-enabled'`).Scan(&pfID)
		seedRemediationRequest(t, pool, "rr-older", "rt-multi", "windows-firewall-enabled", "failed", time.Now().Add(time.Minute))
		seedRemediationRequest(t, pool, "rr-newer", "rt-multi", "windows-firewall-enabled", "completed", time.Now().Add(2*time.Minute))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		lr := got["latestRemediation"].(map[string]any)
		if lr["id"] != "rr-newer" {
			t.Errorf("latestRemediation.id = %v, want rr-newer (newest by requested_at)", lr["id"])
		}
	})
}

func TestGetPostureFinding_AttemptFromPriorEpisode_NotSurfaced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('rt-prior', 'RT-PRIOR')`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rt-prior', 'rt-prior', 'windows-firewall-enabled', 'security-configuration', 'Windows Firewall disabled', 'High', 'open', NOW(), NOW(), NOW())`)

		priorStart := time.Now().Add(-48 * time.Hour)
		priorEnd := time.Now().Add(-24 * time.Hour)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, resolved_at)
			 VALUES ('fs-rt-prior', 'pf-rt-prior', 'High', $1, $2, 'resolved', $2)`,
			priorStart, priorEnd)
		seedRemediationRequest(t, pool, "rr-prior-episode", "rt-prior", "windows-firewall-enabled", "completed", priorStart.Add(time.Hour))

		currentStart := time.Now().Add(-time.Hour)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status)
			 VALUES ('fs-rt-current', 'pf-rt-prior', 'High', $1, $2, 'active')`,
			currentStart, time.Now().Add(time.Hour))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "pf-rt-prior")
		w := httptest.NewRecorder()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.GetPostureFinding(w, req)

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if _, present := got["latestRemediation"]; present {
			t.Errorf("latestRemediation present = %v, want absent (only attempt is from a prior, closed episode)", got["latestRemediation"])
		}
	})
}

func TestGetPostureFinding_RemediationInProgress_ReflectsStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	cases := []struct {
		name           string
		status         string
		wantInProgress bool
	}{
		{"non-terminal status is in progress", "verifying", true},
		{"terminal status is not in progress", "completed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				h := newPostureTestHandler(t, pool)
				agentID := "rt-inprog-" + c.status
				seedPostureCheckRun(t, pool, "rt-run-"+c.status, agentID, "fail", time.Now())
				h.upsertPostureFindingsForRun(context.Background(), "rt-run-"+c.status)

				var pfID string
				pool.QueryRow(context.Background(),
					`SELECT id FROM posture_findings WHERE agent_id=$1 AND check_id='windows-firewall-enabled'`, agentID).Scan(&pfID)
				seedRemediationRequest(t, pool, "rr-"+c.status, agentID, "windows-firewall-enabled", c.status, time.Now().Add(time.Minute))

				req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
				w := httptest.NewRecorder()
				h.GetPostureFinding(w, req)

				var got map[string]any
				json.Unmarshal(w.Body.Bytes(), &got)
				lr := got["latestRemediation"].(map[string]any)
				if lr["inProgress"] != c.wantInProgress {
					t.Errorf("inProgress = %v, want %v", lr["inProgress"], c.wantInProgress)
				}
			})
		})
	}
}

func TestGetPostureFinding_StaleDispatchedAttempt_ReapedToTimedOut(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-stale-get", "rt-stale-get", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-stale-get")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='rt-stale-get' AND check_id='windows-firewall-enabled'`).Scan(&pfID)
		mustExecAPI(t, pool,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at, dispatched_at)
			 VALUES ('rr-stale-get', 'test-remediation', 'rt-stale-get', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', $1, $2)`,
			time.Now().Add(time.Minute), time.Now().Add(-2*time.Hour))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		lr := got["latestRemediation"].(map[string]any)
		if lr["status"] != "timed_out" {
			t.Errorf("status = %v, want timed_out (GetPostureFinding must reap a stale dispatched attempt)", lr["status"])
		}

		var dbStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id='rr-stale-get'`).Scan(&dbStatus)
		if dbStatus != "timed_out" {
			t.Errorf("db status = %q, want timed_out (reap must persist, not just affect the response)", dbStatus)
		}
	})
}

func TestListAgentPostureFindings_StaleDispatchedAttempt_NotReaped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-stale-list", "rt-stale-list", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-stale-list")
		mustExecAPI(t, pool,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at, dispatched_at)
			 VALUES ('rr-stale-list', 'test-remediation', 'rt-stale-list', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', $1, $2)`,
			time.Now().Add(time.Minute), time.Now().Add(-2*time.Hour))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "rt-stale-list")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		lr := got[0]["latestRemediation"].(map[string]any)
		if lr["status"] != "dispatched" {
			t.Errorf("status = %v, want still dispatched (ListAgentPostureFindings must NOT reap, matching ListAgentRemediations' precedent)", lr["status"])
		}
	})
}
