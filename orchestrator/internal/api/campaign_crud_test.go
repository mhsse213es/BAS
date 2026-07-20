package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func createCampaignReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/campaigns", bytes.NewReader(b))
}

func TestCreateCampaign_ValidationErrors(t *testing.T) {
	sc, engine := minimalPostureScenario(t, "cc-validation-sc")
	h := New(nil, ws.NewHub(), engine, "")
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing name", map[string]any{"scenarioId": sc.ID, "agentIds": []string{"a1"}}},
		{"missing scenarioId", map[string]any{"name": "x", "agentIds": []string{"a1"}}},
		{"empty agentIds", map[string]any{"name": "x", "scenarioId": sc.ID, "agentIds": []string{}}},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(c.body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
		}
	}
}

func TestCreateCampaign_ScenarioNotFound(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	h := New(nil, ws.NewHub(), engine, "")
	rec := httptest.NewRecorder()
	h.CreateCampaign(rec, createCampaignReq(map[string]any{"name": "x", "scenarioId": "nope", "agentIds": []string{"a1"}}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestCreateCampaign_InvalidMode(t *testing.T) {
	sc, engine := minimalPostureScenario(t, "cc-badmode-sc")
	h := New(nil, ws.NewHub(), engine, "")
	rec := httptest.NewRecorder()
	h.CreateCampaign(rec, createCampaignReq(map[string]any{
		"name": "x", "scenarioId": sc.ID, "agentIds": []string{"a1"}, "mode": "bogus",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestCreateCampaign_LiveModeRequiresConfirm pins that CreateCampaign applies
// the same live-execution gate as RunScenario (exhaustively tested there —
// see run_scenario_gates_test.go) at the campaign level, without
// re-deriving every gate combination here.
func TestCreateCampaign_LiveModeRequiresConfirm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "cc-live-sc")
		h := New(pool, ws.NewHub(), engine, "")
		seedActiveAgent(t, pool, "cc-live-agent", "Windows")
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "agentIds": []string{"cc-live-agent"}, "mode": "telemetry",
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (confirmLive missing), body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestCreateCampaign_NonExecutableScenario_LiveRejected pins the Executable
// gate: a posture-only scenario (Executable=false) cannot be launched live,
// mirroring RunScenario's own guard.
func TestCreateCampaign_NonExecutableScenario_LiveRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "cc-nonexec-sc") // Executable defaults false
		h := New(pool, ws.NewHub(), engine, "")
		seedActiveAgent(t, pool, "cc-nonexec-agent", "Windows")
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "agentIds": []string{"cc-nonexec-agent"},
			"mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (scenario not executable), body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestCreateCampaign_LabModeRequiresConfirmLab pins the second approval gate:
// lab mode needs confirmLab in addition to confirmLive.
func TestCreateCampaign_LabModeRequiresConfirmLab(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "cc-lab-sc")
		h := New(pool, ws.NewHub(), engine, "")
		seedActiveAgent(t, pool, "cc-lab-agent", "Windows")
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "agentIds": []string{"cc-lab-agent"},
			"mode": "lab", "confirmLive": true,
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (confirmLab missing), body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestCreateCampaign_ExecutionWindowRejection mirrors
// TestRunScenario_ExecutionWindowRejection at the campaign level: an
// execution window that isn't "now" rejects with 400, and a malformed window
// string is an internal error (500) rather than silently passing.
func TestCreateCampaign_ExecutionWindowRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "cc-window-sc")
		sc.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "00:00-00:01"}
		if err := engine.Save(sc); err != nil {
			t.Fatalf("re-save with LivePolicy: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")
		seedActiveAgent(t, pool, "cc-window-agent", "Windows")
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": sc.ID, "agentIds": []string{"cc-window-agent"},
			"mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("outside window: status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}

		badSc, badEngine := minimalLiveScenario(t, "cc-badwindow-sc")
		badSc.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "not-a-window"}
		if err := badEngine.Save(badSc); err != nil {
			t.Fatalf("re-save with bad LivePolicy: %v", err)
		}
		h2 := New(pool, ws.NewHub(), badEngine, "")
		rec2 := httptest.NewRecorder()
		h2.CreateCampaign(rec2, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": badSc.ID, "agentIds": []string{"cc-window-agent"},
			"mode": "telemetry", "confirmLive": true,
		}))
		if rec2.Code != http.StatusInternalServerError {
			t.Fatalf("malformed window: status = %d, want 500, body = %s", rec2.Code, rec2.Body.String())
		}
	})
}

// TestCreateCampaign_RecordsInitiatedByFromClaims pins that campaigns.created_by
// is stamped from the authenticated caller (auth.ClaimsFrom, via the real JWT
// middleware — see callAuthed), not left null.
func TestCreateCampaign_RecordsInitiatedByFromClaims(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "cc-claims-sc")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "cc-claims-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		uid := seedUser(t, pool, "cc-claims-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"name": "x", "scenarioId": sc.ID, "agentIds": []string{agentID}})
		req := authedRequest(t, http.MethodPost, "/api/campaigns", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateCampaign, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		campID, _ := out["campaignId"].(string)

		var createdBy string
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE(created_by,'') FROM campaigns WHERE id=$1`, campID,
		).Scan(&createdBy); err != nil {
			t.Fatalf("query created_by: %v", err)
		}
		if createdBy != uid {
			t.Fatalf("created_by = %q, want %q", createdBy, uid)
		}
	})
}

// TestCreateCampaign_FanOutDispatchedAndSkipped is the core contract: one
// online agent gets dispatched (a scenario_runs row with campaign_id set),
// one offline agent is recorded as a skip — dispatched+skipped reconciles to
// len(agentIds), and the campaigns row persists targets/skips/mode.
func TestCreateCampaign_FanOutDispatchedAndSkipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "cc-fanout-sc")
		h := New(pool, ws.NewHub(), engine, "")

		online := "cc-fanout-online"
		offline := "cc-fanout-offline"
		seedActiveAgent(t, pool, online, "Windows")
		seedActiveAgent(t, pool, offline, "Windows")
		fake := startFakeAgent(t, h.hub, online)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "Fanout Campaign", "scenarioId": sc.ID, "agentIds": []string{online, offline},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if d, _ := out["dispatched"].(float64); d != 1 {
			t.Errorf("dispatched = %v, want 1", out["dispatched"])
		}
		if s, _ := out["skipped"].(float64); s != 1 {
			t.Errorf("skipped = %v, want 1", out["skipped"])
		}
		campID, _ := out["campaignId"].(string)
		if campID == "" {
			t.Fatal("campaignId missing from response")
		}

		var mode string
		var targetsRaw, skipsRaw []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT mode, targets, skips FROM campaigns WHERE id=$1`, campID,
		).Scan(&mode, &targetsRaw, &skipsRaw); err != nil {
			t.Fatalf("query campaign row: %v", err)
		}
		if mode != "posture" {
			t.Errorf("mode = %q, want posture (default)", mode)
		}
		var targets []string
		json.Unmarshal(targetsRaw, &targets)
		if len(targets) != 2 {
			t.Errorf("targets = %v, want 2 entries", targets)
		}
		var skips []map[string]string
		json.Unmarshal(skipsRaw, &skips)
		if len(skips) != 1 || skips[0]["agentId"] != offline || skips[0]["reason"] != "offline" {
			t.Errorf("skips = %v, want [{agentId:%s reason:offline}]", skips, offline)
		}

		// dispatchRun inserts the scenario_runs row before checking connectivity,
		// then flips an unreachable dispatch's row to status='failed' rather than
		// deleting it (an audit trail of the attempt) — so both agents leave a
		// row; only their status differs.
		var onlineStatus, offlineStatus string
		if err := pool.QueryRow(context.Background(),
			`SELECT status FROM scenario_runs WHERE campaign_id=$1 AND agent_id=$2`, campID, online,
		).Scan(&onlineStatus); err != nil {
			t.Fatalf("query online child run: %v", err)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT status FROM scenario_runs WHERE campaign_id=$1 AND agent_id=$2`, campID, offline,
		).Scan(&offlineStatus); err != nil {
			t.Fatalf("query offline child run: %v", err)
		}
		if onlineStatus != "running" {
			t.Errorf("online agent's run status = %q, want running", onlineStatus)
		}
		if offlineStatus != "failed" {
			t.Errorf("offline agent's run status = %q, want failed", offlineStatus)
		}
	})
}

func TestCreateCampaign_ExecutionPolicyFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "user-step", TechniqueID: "T1059", Framework: "custom", Command: "echo user",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		sc, engine := minimalLiveScenario(t, "cc-execpolicy-sc", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "cc-execpolicy-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "ExecPolicy Campaign", "scenarioId": sc.ID, "agentIds": []string{agentID},
			"mode": "telemetry", "confirmLive": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-step] (admin-step must be filtered)", cmd.Steps)
		}

		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		campID, _ := out["campaignId"].(string)
		if campID == "" {
			t.Fatal("campaignId missing from response")
		}

		var skippedJSON, subsetJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT sr.policy_skipped_results, c.subset
			   FROM scenario_runs sr JOIN campaigns c ON c.id = sr.campaign_id
			  WHERE sr.campaign_id=$1 AND sr.agent_id=$2`,
			campID, agentID,
		).Scan(&skippedJSON, &subsetJSON); err != nil {
			t.Fatalf("query policy_skipped_results/subset: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal policy_skipped_results: %v", err)
		}
		if len(skipped) != 1 || skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("policy_skipped_results = %+v, want 1 policy-privilege skip", skipped)
		}

		var subset map[string]any
		json.Unmarshal(subsetJSON, &subset)
		ep, _ := subset["executionPolicy"].(map[string]any)
		if ep["maxPrivilege"] != "user" {
			t.Fatalf("campaigns.subset executionPolicy = %+v, want maxPrivilege=user", subset)
		}
	})
}

func TestListCampaigns_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListCampaigns(rec, httptest.NewRequest(http.MethodGet, "/api/campaigns", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("expected 0 campaigns, got %d", len(out))
		}
	})
}

func TestListCampaigns_ReturnsRollup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaign(t, pool, "lc-camp", "List Rollup Scenario")
		seedReportableRun(t, pool, "lc-camp-run", "lc-camp-agent", reportRunOpts{CampaignID: "lc-camp"})
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListCampaigns(rec, httptest.NewRequest(http.MethodGet, "/api/campaigns", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		var found map[string]any
		for _, c := range out {
			if c["id"] == "lc-camp" {
				found = c
			}
		}
		if found == nil {
			t.Fatal("seeded campaign not in list")
		}
		summary, _ := found["summary"].(map[string]any)
		if summary == nil {
			t.Fatal("summary missing from list entry")
		}
	})
}

func TestGetCampaign_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetCampaign(rec, campaignReq("/api/campaigns/nope", "nope", ""))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetCampaign_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaign(t, pool, "gc-camp", "Get Campaign Scenario")
		seedReportableRun(t, pool, "gc-camp-run", "gc-camp-agent", reportRunOpts{CampaignID: "gc-camp"})
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetCampaign(rec, campaignReq("/api/campaigns/gc-camp", "gc-camp", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out["id"] != "gc-camp" {
			t.Fatalf("id = %v", out["id"])
		}
		runs, _ := out["runs"].([]any)
		if len(runs) != 1 {
			t.Fatalf("runs = %v, want 1 entry", out["runs"])
		}
		if out["summary"] == nil {
			t.Error("summary missing")
		}
	})
}

func TestCampaignSummary_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.CampaignSummary(rec, campaignReq("/api/campaigns/nope/summary", "nope", ""))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestCampaignSummary_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaign(t, pool, "cs-camp", "Summary Scenario")
		seedReportableRun(t, pool, "cs-camp-run", "cs-camp-agent", reportRunOpts{CampaignID: "cs-camp"})
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.CampaignSummary(rec, campaignReq("/api/campaigns/cs-camp/summary", "cs-camp", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var s map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, ok := s["status"]; !ok {
			t.Error("summary missing status field")
		}
	})
}

func TestStopCampaign_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.StopCampaign(rec, campaignReq("/api/campaigns/nope/stop", "nope", ""))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestStopCampaign_MarksStoppedAndFreesRunningChildren pins: stopped_at gets
// set, a still-running child run is freed to 'partial' (its executed steps
// stand — see StopCampaign's doc comment), and the cancelled count in the
// response matches.
func TestStopCampaign_MarksStoppedAndFreesRunningChildren(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaign(t, pool, "sc-camp", "Stop Campaign Scenario")
		seedReportableRun(t, pool, "sc-camp-run", "sc-camp-agent", reportRunOpts{CampaignID: "sc-camp", Status: "running"})
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		rec := httptest.NewRecorder()
		h.StopCampaign(rec, campaignReq("/api/campaigns/sc-camp/stop", "sc-camp", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["stopped"] != true {
			t.Errorf("stopped = %v, want true", out["stopped"])
		}
		if c, _ := out["cancelled"].(float64); c != 1 {
			t.Errorf("cancelled = %v, want 1", out["cancelled"])
		}

		var stoppedAt *time.Time
		var childStatus string
		pool.QueryRow(context.Background(), `SELECT stopped_at FROM campaigns WHERE id='sc-camp'`).Scan(&stoppedAt)
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id='sc-camp-run'`).Scan(&childStatus)
		if stoppedAt == nil {
			t.Error("stopped_at not set")
		}
		if childStatus != "partial" {
			t.Errorf("child run status = %q, want partial", childStatus)
		}
	})
}

// TestStopCampaign_Running_AgentOnline pins: when a running child's agent is
// connected, StopCampaign sends it command_cancel (mirroring CancelRun) instead
// of relabeling the row immediately — the agent must actually stop executing,
// not keep running unaware and later heal the row back past the cancellation.
func TestStopCampaign_Running_AgentOnline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "sc-camp-online-agent"
		runID := "sc-camp-online-run"
		seedCampaign(t, pool, "sc-camp-online", "Stop Campaign Online Scenario")
		seedReportableRun(t, pool, runID, agentID, reportRunOpts{CampaignID: "sc-camp-online", Status: "running"})
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.StopCampaign(rec, campaignReq("/api/campaigns/sc-camp-online/stop", "sc-camp-online", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandCancel {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgCommandCancel)
		}
		var data map[string]string
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode command data: %v", err)
		}
		if data["runId"] != runID {
			t.Fatalf("command data = %+v, want runId=%s", data, runID)
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, runID).Scan(&status); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "running" {
			t.Fatalf("run status = %q, want still running (agent will report back)", status)
		}
	})
}

// TestStopCampaign_Idempotent pins that stopping an already-stopped campaign
// still returns 200 (not 404) — RowsAffected()==0 must be disambiguated from
// "campaign not found" by re-checking existence.
func TestStopCampaign_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaign(t, pool, "sc-idem-camp", "Idempotent Stop Scenario")
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		rec1 := httptest.NewRecorder()
		h.StopCampaign(rec1, campaignReq("/api/campaigns/sc-idem-camp/stop", "sc-idem-camp", ""))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first stop: status = %d, want 200", rec1.Code)
		}

		rec2 := httptest.NewRecorder()
		h.StopCampaign(rec2, campaignReq("/api/campaigns/sc-idem-camp/stop", "sc-idem-camp", ""))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second stop: status = %d, want 200 (not 404)", rec2.Code)
		}
	})
}

// TestCampaignSummary_LazyStampsCompletedAt pins summaryFor's side effect:
// the first read that observes every child in a terminal state stamps
// completed_at, without the campaign being explicitly stopped.
func TestCampaignSummary_LazyStampsCompletedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaign(t, pool, "lazy-camp", "Lazy Complete Scenario")
		seedReportableRun(t, pool, "lazy-camp-run", "lazy-camp-agent", reportRunOpts{CampaignID: "lazy-camp", Status: "completed"})
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		var before *time.Time
		pool.QueryRow(context.Background(), `SELECT completed_at FROM campaigns WHERE id='lazy-camp'`).Scan(&before)
		if before != nil {
			t.Fatal("precondition: completed_at should start nil")
		}

		rec := httptest.NewRecorder()
		h.CampaignSummary(rec, campaignReq("/api/campaigns/lazy-camp/summary", "lazy-camp", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}

		var after *time.Time
		pool.QueryRow(context.Background(), `SELECT completed_at FROM campaigns WHERE id='lazy-camp'`).Scan(&after)
		if after == nil {
			t.Error("completed_at should be stamped once every child reads terminal")
		}
	})
}
