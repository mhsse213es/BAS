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
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunScenarioIntegration_PostureEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "int-posture")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-posture"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["status"] != "dispatched" || resp["mode"] != "posture" || resp["runId"] == "" {
			t.Fatalf("resp = %+v, want status=dispatched mode=posture runId=<non-empty>", resp)
		}
		if _, hasWarning := resp["osWarning"]; hasWarning {
			t.Fatalf("resp unexpectedly has osWarning: %+v", resp)
		}
		fake.WaitForMessage(t, 2*time.Second)
	})
}

func TestRunScenarioIntegration_LiveEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-live")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-live"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["mode"] != "telemetry" {
			t.Fatalf("resp = %+v, want mode=telemetry", resp)
		}
		fake.WaitForMessage(t, 2*time.Second)
	})
}

func TestRunScenarioIntegration_SkipReasonsSurfaceCorrectStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "int-skips")
		h := New(pool, ws.NewHub(), engine, "")

		busyAgent := "int-agent-busy"
		seedActiveAgent(t, pool, busyAgent, "Windows")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at) VALUES ('int-run-busy',$1,$2,'x','running',NOW())`,
			sc.ID, busyAgent); err != nil {
			t.Fatalf("seed busy run: %v", err)
		}
		busyRec := httptest.NewRecorder()
		h.RunScenario(busyRec, runScenarioReq(sc.ID, map[string]any{"agentId": busyAgent}))
		if busyRec.Code != http.StatusConflict {
			t.Fatalf("busy: status = %d, want 409", busyRec.Code)
		}

		offlineAgent := "int-agent-offline"
		seedActiveAgent(t, pool, offlineAgent, "Windows")
		offlineRec := httptest.NewRecorder()
		h.RunScenario(offlineRec, runScenarioReq(sc.ID, map[string]any{"agentId": offlineAgent}))
		if offlineRec.Code != http.StatusServiceUnavailable {
			t.Fatalf("offline: status = %d, want 503", offlineRec.Code)
		}

		// The run this dispatch created must persist a genuine reason, not just
		// a bare status='failed' with nothing to explain it -- see
		// project_environmental_error_triage.md-adjacent gap: a Failed run
		// previously showed "0 fail / 0 pass" with zero indication of why.
		listRec := httptest.NewRecorder()
		h.ListScenarioRuns(listRec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId="+offlineAgent, nil))
		var runs []runRow
		if err := json.Unmarshal(listRec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 1 {
			t.Fatalf("runs = %d, want 1", len(runs))
		}
		if runs[0].Status != "failed" {
			t.Fatalf("Status = %q, want failed", runs[0].Status)
		}
		if runs[0].FailReason == "" || !strings.Contains(strings.ToLower(runs[0].FailReason), "offline") {
			t.Fatalf("FailReason = %q, want a genuine reason mentioning the agent is offline", runs[0].FailReason)
		}
	})
}

func TestRunScenarioIntegration_TechniqueAndStepSubset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"},
			{Name: "step-1", TechniqueID: "T1059", Framework: "custom", Command: "echo 1"},
		}
		sc, engine := minimalLiveScenario(t, "int-subset", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-subset"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true, "steps": []int{0},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "step-0" {
			t.Fatalf("cmd.Steps = %+v, want exactly [step-0]", cmd.Steps)
		}

		// dispatch_subset must persist the exact request verbatim -- this is
		// what lets Re-run replay this run exactly instead of reconstructing
		// (lossily, for steps) from results after the fact.
		var subsetRaw []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT dispatch_subset FROM scenario_runs WHERE agent_id = $1`, agentID,
		).Scan(&subsetRaw); err != nil {
			t.Fatalf("query dispatch_subset: %v", err)
		}
		var subset models.DispatchSubset
		if err := json.Unmarshal(subsetRaw, &subset); err != nil {
			t.Fatalf("decode dispatch_subset: %v", err)
		}
		if subset.Field != "steps" || len(subset.IDs) != 1 || subset.IDs[0] != "0" {
			t.Fatalf("dispatch_subset = %+v, want {field:steps ids:[0]}", subset)
		}

		// And it must round-trip through the same list endpoint the frontend's
		// Re-run Review reads (GET /api/scenarios/runs).
		listRec := httptest.NewRecorder()
		h.ListScenarioRuns(listRec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId="+agentID, nil))
		var runs []struct {
			DispatchSubset *models.DispatchSubset `json:"dispatchSubset"`
		}
		if err := json.Unmarshal(listRec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(runs) != 1 || runs[0].DispatchSubset == nil || runs[0].DispatchSubset.Field != "steps" {
			t.Fatalf("ListScenarioRuns runs = %+v, want one run with dispatchSubset.field=steps", runs)
		}
	})
}

func TestRunScenarioIntegration_MaxPrivilegeFiltersStep(t *testing.T) {
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
		sc, engine := minimalLiveScenario(t, "int-maxpriv-mixed", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-maxpriv-mixed"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-step] (admin-step must be filtered)", cmd.Steps)
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("read policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal policy_skipped_results: %v", err)
		}
		if len(skipped) != 1 {
			t.Fatalf("policy_skipped_results = %d entries, want 1", len(skipped))
		}
		if skipped[0].Result != models.ResultSkipped {
			t.Errorf("skipped[0].Result = %q, want %q", skipped[0].Result, models.ResultSkipped)
		}
		if skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Errorf("skipped[0].SkipReason = %q, want %q", skipped[0].SkipReason, models.SkipReasonPolicyPrivilege)
		}
		if skipped[0].Technique.ID != "T1548" {
			t.Errorf("skipped[0].Technique.ID = %q, want T1548", skipped[0].Technique.ID)
		}

		var stepsTotalBase, stepsEligibleBase int
		if err := pool.QueryRow(context.Background(),
			`SELECT steps_total_base, steps_eligible_base FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&stepsTotalBase, &stepsEligibleBase); err != nil {
			t.Fatalf("read coverage columns: %v", err)
		}
		if stepsTotalBase != 2 {
			t.Errorf("steps_total_base = %d, want 2 (both steps, before filtering)", stepsTotalBase)
		}
		if stepsEligibleBase != 1 {
			t.Errorf("steps_eligible_base = %d, want 1 (user-step only, after policy filter)", stepsEligibleBase)
		}
	})
}

// TestRunScenarioIntegration_SkipsStepMissingPrerequisite mirrors
// TestRunScenarioIntegration_MaxPrivilegeFiltersStep's shape for the new
// environmental-prerequisite filter: T1087.002 requires domain_joined=true
// (see scenario.PrerequisiteFor); against a non-domain-joined agent it must
// be skipped while an unrelated step in the same run dispatches normally.
func TestRunScenarioIntegration_SkipsStepMissingPrerequisite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "unrelated-step", TechniqueID: "T1082", Framework: "custom", Command: "echo hi",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "domain-step", TechniqueID: "T1087.002", Framework: "custom", Command: "echo domain",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
		}
		sc, engine := minimalLiveScenario(t, "int-prereq-missing", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-prereq-missing"
		seedActiveAgent(t, pool, agentID, "Windows")
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET domain_joined = false WHERE agent_id = $1`, agentID); err != nil {
			t.Fatalf("seed domain_joined=false: %v", err)
		}
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "unrelated-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [unrelated-step] (domain-step must be filtered)", cmd.Steps)
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("read policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal policy_skipped_results: %v", err)
		}
		if len(skipped) != 1 {
			t.Fatalf("policy_skipped_results = %d entries, want 1", len(skipped))
		}
		if skipped[0].Result != models.ResultSkipped {
			t.Errorf("skipped[0].Result = %q, want %q", skipped[0].Result, models.ResultSkipped)
		}
		if skipped[0].SkipReason != models.SkipReasonPrerequisiteMissing {
			t.Errorf("skipped[0].SkipReason = %q, want %q", skipped[0].SkipReason, models.SkipReasonPrerequisiteMissing)
		}
		if skipped[0].Technique.ID != "T1087.002" {
			t.Errorf("skipped[0].Technique.ID = %q, want T1087.002", skipped[0].Technique.ID)
		}
	})
}

// TestRunScenarioIntegration_UnknownDomainJoinedNeverGates confirms the
// Error-handling contract: an agent that has never reported domain_joined
// (NULL) must never have a curated technique skipped on its account.
func TestRunScenarioIntegration_UnknownDomainJoinedNeverGates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "domain-step", TechniqueID: "T1087.002", Framework: "custom", Command: "echo domain",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
		}
		sc, engine := minimalLiveScenario(t, "int-prereq-unknown", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-prereq-unknown"
		seedActiveAgent(t, pool, agentID, "Windows") // domain_joined left NULL -- never set
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "domain-step" {
			t.Fatalf("cmd.Steps = %+v, want [domain-step] dispatched normally (domain_joined unknown must never gate)", cmd.Steps)
		}
	})
}

// The operator's chosen mode and privilege ceiling were previously discarded
// after dispatch -- only their downstream effects (which steps got skipped)
// were visible, with no way to tell "was this the admin run or the no-limit
// run?" after the fact. This confirms both are persisted on the run row and
// readable back through the same ListScenarioRuns endpoint the Results/Live
// views use.
func TestRunScenarioIntegration_ModeAndMaxPrivilegePersisted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-mode-maxpriv")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-mode-maxpriv"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
			"executionPolicy": map[string]any{"maxPrivilege": "admin"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}
		fake.WaitForMessage(t, 2*time.Second)

		listRec := httptest.NewRecorder()
		h.ListScenarioRuns(listRec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId="+agentID, nil))
		if listRec.Code != http.StatusOK {
			t.Fatalf("ListScenarioRuns status = %d, body = %s", listRec.Code, listRec.Body.String())
		}
		var runs []runRow
		if err := json.Unmarshal(listRec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode runs: %v", err)
		}
		if len(runs) != 1 {
			t.Fatalf("runs = %d, want 1", len(runs))
		}
		if runs[0].Mode != "telemetry" {
			t.Errorf("runs[0].Mode = %q, want %q", runs[0].Mode, "telemetry")
		}
		if runs[0].MaxPrivilege != "admin" {
			t.Errorf("runs[0].MaxPrivilege = %q, want %q", runs[0].MaxPrivilege, "admin")
		}
	})
}

func TestRunScenarioIntegration_MaxPrivilegeAllFilteredCompletesImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		sc, engine := minimalLiveScenario(t, "int-maxpriv-all", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-maxpriv-all"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}

		var status string
		var resultsJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT status, results FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&status, &resultsJSON); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "completed" {
			t.Fatalf("status = %q, want completed (run should finish immediately, no agent round-trip)", status)
		}
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsJSON, &results)
		if len(results) != 1 || results[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("results = %+v, want exactly 1 policy-privilege skip", results)
		}

		var stepsTotalBase, stepsEligibleBase int
		if err := pool.QueryRow(context.Background(),
			`SELECT steps_total_base, steps_eligible_base FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&stepsTotalBase, &stepsEligibleBase); err != nil {
			t.Fatalf("read coverage columns: %v", err)
		}
		if stepsTotalBase != 1 {
			t.Errorf("steps_total_base = %d, want 1", stepsTotalBase)
		}
		if stepsEligibleBase != 0 {
			t.Errorf("steps_eligible_base = %d, want 0 (every step was policy-filtered)", stepsEligibleBase)
		}
	})
}

func TestRunScenarioIntegration_PostureOSMismatchStillDispatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "int-osw")
		sc.SupportedOS = []string{"linux"}
		if err := engine.SaveAs(context.Background(), sc, "user:test"); err != nil {
			t.Fatalf("re-save: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-osw"
		seedActiveAgent(t, pool, agentID, "Windows Server 2022")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["osWarning"] == nil || resp["osWarning"] == "" {
			t.Fatalf("resp = %+v, want a populated osWarning", resp)
		}
		fake.WaitForMessage(t, 2*time.Second)
	})
}

// Proves the full pause/resume round-trip: dispatch a live run, pause it
// (asserting the agent receives command_pause), simulate the agent's
// confirmation the way a real one would (POSTing a "paused" run event),
// assert ListScenarioRuns reflects paused=true, then symmetrically resume.
func TestRunScenarioIntegration_PauseResumeRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-pause-resume")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-pause-resume"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("dispatch status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}
		fake.WaitForMessage(t, 2*time.Second) // drain command_scenario

		// -- Pause --
		pauseRec := httptest.NewRecorder()
		h.PauseRun(pauseRec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/pause", nil), "runId", runID))
		if pauseRec.Code != http.StatusOK {
			t.Fatalf("pause status = %d, body = %s", pauseRec.Code, pauseRec.Body.String())
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandPause {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandPause)
		}

		// Simulate the agent's real confirmation (agent.go's pauseCurrentScenario
		// would emit exactly this through the same batched event pipeline).
		postEvents(t, h, []map[string]any{
			{"runId": runID, "seq": 100, "type": "paused", "ts": "2026-06-09T16:40:12Z"},
		})

		listRec := httptest.NewRecorder()
		h.ListScenarioRuns(listRec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId="+agentID, nil))
		var runs []runRow
		_ = json.Unmarshal(listRec.Body.Bytes(), &runs)
		if len(runs) != 1 || !runs[0].Paused {
			t.Fatalf("after pause: runs = %+v, want exactly 1 run with Paused=true", runs)
		}
		if runs[0].Status != "running" {
			t.Errorf("Status = %q, want unchanged %q (pause never touches status)", runs[0].Status, "running")
		}

		// -- Resume --
		resumeRec := httptest.NewRecorder()
		h.ResumeRun(resumeRec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/resume", nil), "runId", runID))
		if resumeRec.Code != http.StatusOK {
			t.Fatalf("resume status = %d, body = %s", resumeRec.Code, resumeRec.Body.String())
		}
		env2 := fake.WaitForMessage(t, 2*time.Second)
		if env2.Type != models.MsgCommandResume {
			t.Fatalf("WS message type = %q, want %q", env2.Type, models.MsgCommandResume)
		}

		postEvents(t, h, []map[string]any{
			{"runId": runID, "seq": 101, "type": "resumed", "ts": "2026-06-09T16:40:13Z"},
		})

		listRec2 := httptest.NewRecorder()
		h.ListScenarioRuns(listRec2, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId="+agentID, nil))
		var runs2 []runRow
		_ = json.Unmarshal(listRec2.Body.Bytes(), &runs2)
		if len(runs2) != 1 || runs2[0].Paused {
			t.Fatalf("after resume: runs = %+v, want exactly 1 run with Paused=false", runs2)
		}
	})
}
