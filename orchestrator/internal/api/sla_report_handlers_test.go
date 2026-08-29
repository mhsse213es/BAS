package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetSLAReport_ComputesFromSeededEpisodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('rpt-a1', 'RPT-A1')`)

		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rpt-1', 'rpt-a1', 'windows-firewall-enabled', 'security-configuration', 'Windows Firewall disabled', 'High', 'remediated', NOW(), NOW(), NOW())`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rpt-2', 'rpt-a1', 'windows-smbv1-disabled', 'security-configuration', 'SMBv1 enabled', 'High', 'remediated', NOW(), NOW(), NOW())`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rpt-3', 'rpt-a1', 'linux-firewall-enabled', 'security-configuration', 'UFW not active', 'Critical', 'open', NOW(), NOW(), NOW())`)

		deadline := time.Now().Add(-time.Hour)
		onTimeResolved := deadline.Add(-time.Minute)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, resolved_at)
			 VALUES ('fs-rpt-1', 'pf-rpt-1', 'High', $1, $2, 'resolved', $3)`,
			deadline.Add(-72*time.Hour), deadline, onTimeResolved)

		lateResolved := deadline.Add(time.Minute)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, resolved_at)
			 VALUES ('fs-rpt-2', 'pf-rpt-2', 'High', $1, $2, 'resolved', $3)`,
			deadline.Add(-72*time.Hour), deadline, lateResolved)

		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status)
			 VALUES ('fs-rpt-3', 'pf-rpt-3', 'Critical', NOW(), $1, 'active')`,
			time.Now().Add(time.Hour))

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/report", nil)
		w := httptest.NewRecorder()
		h.GetSLAReport(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		overall := got["overall"].(map[string]any)
		if overall["totalEpisodes"].(float64) != 3 {
			t.Errorf("overall.totalEpisodes = %v, want 3", overall["totalEpisodes"])
		}
		if overall["currentlyOpen"].(float64) != 1 {
			t.Errorf("overall.currentlyOpen = %v, want 1", overall["currentlyOpen"])
		}
		if overall["onTime"].(float64) != 1 || overall["late"].(float64) != 1 {
			t.Errorf("overall onTime/late = %v/%v, want 1/1", overall["onTime"], overall["late"])
		}

		bySeverity := got["bySeverity"].([]any)
		if len(bySeverity) != 2 {
			t.Fatalf("bySeverity = %v, want 2 rows (High, Critical)", bySeverity)
		}

		recent := got["recentlyResolved"].([]any)
		if len(recent) != 2 {
			t.Fatalf("recentlyResolved = %v, want 2 rows", recent)
		}
		first := recent[0].(map[string]any)
		if first["checkId"] != "windows-smbv1-disabled" || first["onTime"] != false {
			t.Errorf("recentlyResolved[0] = %+v, want checkId=windows-smbv1-disabled onTime=false (most recently resolved first)", first)
		}
	})
}

func TestGetSLAReport_NoEpisodes_ReturnsZeroValuedReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/report", nil)
		w := httptest.NewRecorder()
		h.GetSLAReport(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		overall := got["overall"].(map[string]any)
		if overall["totalEpisodes"].(float64) != 0 {
			t.Errorf("overall.totalEpisodes = %v, want 0", overall["totalEpisodes"])
		}
		if len(got["recentlyResolved"].([]any)) != 0 {
			t.Errorf("recentlyResolved = %v, want empty", got["recentlyResolved"])
		}
	})
}
