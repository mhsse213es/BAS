package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/siem"
	"github.com/jackc/pgx/v5/pgxpool"
)

// siemConfigFor builds a siem.Config pointing at a mock QRadar server, for
// tests that call runSIEMCorrelation directly rather than through the
// TriggerSIEMCorrelation/AutoCorrelateSIEM DB-loading paths.
func siemConfigFor(t *testing.T, pool *pgxpool.Pool, consoleURL string) siem.Config {
	t.Helper()
	return siem.Config{ID: "direct-cfg", Name: "direct", Provider: siem.ProviderQRadar, ConsoleURL: consoleURL, Token: "tok"}
}

// newQRadarMock builds an httptest.Server that implements just enough of
// QRadar's Ariel REST API (system/about, ariel/searches, and its results
// endpoint) for internal/siem's QRadarClient to run a full search: start →
// poll status → fetch results. The status poll always returns COMPLETED on
// the first check, so tests never wait out QRadarClient's 2s poll interval.
// authFail simulates a bad token/credentials (401 on every endpoint).
func newQRadarMock(t *testing.T, events []map[string]any, authFail bool) *httptest.Server {
	t.Helper()
	if events == nil {
		events = []map[string]any{}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authFail {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/console/restapi/api/system/about":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/console/restapi/api/ariel/searches":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"search_id": "mock-search-1"})
		case strings.HasSuffix(r.URL.Path, "/results"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"events": events})
		case strings.HasPrefix(r.URL.Path, "/console/restapi/api/ariel/searches/"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "COMPLETED"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// qradarAlertEvent builds one QRadar-shaped raw event row (matches the
// field names QRadarClient.fetchResults reads: eventid/rule_name/category/
// severity/sourceip/destinationip/username/process_name/command/event_name/
// starttime as epoch-milliseconds).
func qradarAlertEvent(eventID, ruleName, sourceIP string, at time.Time) map[string]any {
	return map[string]any{
		"eventid": eventID, "rule_name": ruleName, "category": "Malware",
		"severity": "8", "sourceip": sourceIP, "destinationip": "10.0.0.1",
		"username": "svc-bas", "process_name": "powershell.exe", "command": "whoami",
		"event_name": "Suspicious PowerShell", "starttime": float64(at.UnixMilli()),
	}
}

func seedSIEMConfig(t *testing.T, pool *pgxpool.Pool, id, provider, consoleURL string, enabled, autoCorrelate bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO siem_configs (id, name, provider, enabled, console_url, token, auto_correlate)
		 VALUES ($1,$2,$3,$4,$5,'tok',$6)`,
		id, "cfg-"+id, provider, enabled, consoleURL, autoCorrelate); err != nil {
		t.Fatalf("seed siem_config: %v", err)
	}
}

func TestTriggerSIEMCorrelation_NoConfigAvailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TriggerSIEMCorrelation(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "runId", "r1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestTriggerSIEMCorrelation_RunNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedSIEMConfig(t, pool, "sc-nf-cfg", "qradar", "https://unused", true, false)
		h := siemHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TriggerSIEMCorrelation(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "runId", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestTriggerSIEMCorrelation_EndToEnd dispatches a real (mocked-QRadar)
// correlation in the background and polls until the siem_correlations row
// appears — TriggerSIEMCorrelation intentionally returns before correlation
// finishes (see its own doc comment), so the test can't just check the HTTP
// response.
func TestTriggerSIEMCorrelation_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runStart := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		alertAt := runStart.Add(30 * time.Second)
		mock := newQRadarMock(t, []map[string]any{qradarAlertEvent("e1", "Suspicious PS", "10.0.0.5", alertAt)}, false)
		defer mock.Close()

		seedSIEMConfig(t, pool, "tsc-e2e-cfg", "qradar", mock.URL, true, false)
		seedActiveAgent(t, pool, "tsc-e2e-agent", "Windows")
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET ip_address='10.0.0.5' WHERE agent_id='tsc-e2e-agent'`); err != nil {
			t.Fatalf("set agent ip: %v", err)
		}
		results := []models.SimulationResult{
			{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell"}, Result: models.ResultFail, ExecutedAt: alertAt, DurationMs: 500},
		}
		resultsJSON, _ := json.Marshal(results)
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, status, results, started_at, completed_at)
			 VALUES ('tsc-e2e-run','sc-x','tsc-e2e-agent','completed',$1,$2,$3)`,
			resultsJSON, runStart, runStart.Add(2*time.Minute)); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		h := siemHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TriggerSIEMCorrelation(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "runId", "tsc-e2e-run"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Status string `json:"status"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Status != "correlating" {
			t.Errorf("status = %q, want correlating (async — correlation hasn't finished yet)", out.Status)
		}

		deadline := time.Now().Add(5 * time.Second)
		var detected int
		for time.Now().Before(deadline) {
			if err := pool.QueryRow(context.Background(),
				`SELECT detected FROM siem_correlations WHERE run_id='tsc-e2e-run'`).Scan(&detected); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if detected != 1 {
			t.Fatalf("detected = %d, want 1 (the mock alert should correlate to T1059.001)", detected)
		}
	})
}

func TestGetSIEMCorrelations_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		empty := httptest.NewRecorder()
		h.GetSIEMCorrelations(empty, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "no-run"))
		var emptyOut []map[string]any
		json.Unmarshal(empty.Body.Bytes(), &emptyOut)
		if len(emptyOut) != 0 {
			t.Fatalf("expected 0 correlations, got %d", len(emptyOut))
		}

		if _, err := pool.Exec(context.Background(),
			`INSERT INTO siem_correlations (run_id, config_id, agent_id, provider, window_start, window_end, total_alerts, detected)
			 VALUES ('gsc-run','cfg1','agent1','qradar',NOW(),NOW(),3,2)`); err != nil {
			t.Fatalf("seed siem_correlation: %v", err)
		}
		rec := httptest.NewRecorder()
		h.GetSIEMCorrelations(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "gsc-run"))
		var out []struct {
			RunID       string `json:"runId"`
			TotalAlerts int    `json:"totalAlerts"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 || out[0].RunID != "gsc-run" || out[0].TotalAlerts != 3 {
			t.Fatalf("out = %+v, want 1 entry for gsc-run with totalAlerts=3", out)
		}
	})
}

// TestRunSIEMCorrelation_UpsertsOnConflict pins the ON CONFLICT (run_id,
// config_id) upsert: calling it twice for the same run+config overwrites the
// existing row rather than erroring or duplicating.
func TestRunSIEMCorrelation_UpsertsOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runStart := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		mock := newQRadarMock(t, nil, false)
		defer mock.Close()
		h := siemHandler(t, pool)
		cfg := siemConfigFor(t, pool, mock.URL)

		results := []models.SimulationResult{
			{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001"}, Result: models.ResultFail, ExecutedAt: runStart},
		}
		if err := h.runSIEMCorrelation(context.Background(), cfg, "rsc-run", "rsc-agent", "10.0.0.9", runStart, runStart.Add(1*time.Minute), results); err != nil {
			t.Fatalf("first correlation: %v", err)
		}
		if err := h.runSIEMCorrelation(context.Background(), cfg, "rsc-run", "rsc-agent", "10.0.0.9", runStart, runStart.Add(1*time.Minute), results); err != nil {
			t.Fatalf("second correlation: %v", err)
		}

		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM siem_correlations WHERE run_id='rsc-run'`).Scan(&n)
		if n != 1 {
			t.Fatalf("row count = %d, want 1 (second call should upsert, not duplicate)", n)
		}
	})
}

// TestAutoCorrelateSIEM_OnlyDispatchesEnabledAutoCorrelateConfigs pins the
// filter: AutoCorrelateSIEM only fires for configs with enabled=true AND
// auto_correlate=true — a disabled config and an enabled-but-manual-only
// config are both skipped.
func TestAutoCorrelateSIEM_OnlyDispatchesEnabledAutoCorrelateConfigs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mock := newQRadarMock(t, nil, false)
		defer mock.Close()
		seedSIEMConfig(t, pool, "auto-on", "qradar", mock.URL, true, true)   // should fire
		seedSIEMConfig(t, pool, "auto-off", "qradar", mock.URL, true, false) // manual only — skipped
		seedSIEMConfig(t, pool, "disabled", "qradar", mock.URL, false, true) // disabled — skipped
		h := siemHandler(t, pool)

		runStart := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		results := []models.SimulationResult{
			{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001"}, Result: models.ResultFail, ExecutedAt: runStart},
		}
		h.AutoCorrelateSIEM("ac-run", "ac-agent", "10.0.0.5", runStart, runStart.Add(1*time.Minute), results)

		deadline := time.Now().Add(5 * time.Second)
		var n int
		for time.Now().Before(deadline) {
			pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM siem_correlations WHERE run_id='ac-run'`).Scan(&n)
			if n > 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if n != 1 {
			t.Fatalf("siem_correlations rows for ac-run = %d, want exactly 1 (only auto-on should fire)", n)
		}
		var configID string
		pool.QueryRow(context.Background(), `SELECT config_id FROM siem_correlations WHERE run_id='ac-run'`).Scan(&configID)
		if configID != "auto-on" {
			t.Fatalf("config_id = %q, want auto-on", configID)
		}
	})
}
