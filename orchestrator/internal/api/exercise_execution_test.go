package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func exerciseExecutionReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/exercises/executions", bytes.NewReader(b))
}

// createPlanDirect seeds a plan straight through the store (no HTTP layer)
// so execution tests don't repeat the CreateExercisePlan flow already
// covered in exercise_plan_test.go.
func createPlanDirect(t *testing.T, h *Handler, name string, steps []exercise.PlanStep, vars []exercise.VarDef) *exercise.Plan {
	t.Helper()
	p := &exercise.Plan{Name: name, Steps: steps, Variables: vars}
	if err := h.exerciseStore.CreatePlan(context.Background(), p); err != nil {
		t.Fatalf("createPlanDirect: %v", err)
	}
	return p
}

func TestListExerciseExecutions_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListExerciseExecutions(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("expected 0 executions, got %d", len(out))
		}
	})
}

func TestGetExerciseExecution_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetExerciseExecution(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestCreateExerciseExecution_MissingPlanID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateExerciseExecution(rec, exerciseExecutionReq(map[string]any{"name": "x"}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateExerciseExecution_PlanNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateExerciseExecution(rec, exerciseExecutionReq(map[string]any{"plan_id": "nope"}))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestCreateExerciseExecution_MissingRequiredVariable pins the
// ValidateVars gate (already exhaustively tested at the package level) is
// actually wired: a plan declaring a required variable rejects an execution
// that doesn't supply it.
func TestCreateExerciseExecution_MissingRequiredVariable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		plan := createPlanDirect(t, h, "needs-var", []exercise.PlanStep{minimalStep("a")},
			[]exercise.VarDef{{Name: "TargetDomain", Required: true}})

		rec := httptest.NewRecorder()
		h.CreateExerciseExecution(rec, exerciseExecutionReq(map[string]any{"plan_id": plan.ID}))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateExerciseExecution_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		plan := createPlanDirect(t, h, "simple", []exercise.PlanStep{minimalStep("a")}, nil)

		rec := httptest.NewRecorder()
		h.CreateExerciseExecution(rec, exerciseExecutionReq(map[string]any{
			"plan_id": plan.ID, "name": "Run 1",
			"targets": []exercise.Target{{ID: "t1", Name: "Alice", Email: "alice@corp.test"}},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			ID          string `json:"id"`
			Status      string `json:"status"`
			PlanVersion int    `json:"plan_version"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Status != "draft" {
			t.Errorf("status = %q, want draft", out.Status)
		}
		// CreatePlan floors the stored version at 1 via max1() but never writes
		// it back onto the in-memory Plan struct, so plan.Version is still 0
		// here — assert against the known DB-assigned value instead.
		if out.PlanVersion != 1 {
			t.Errorf("plan_version = %d, want 1 (snapshot from the newly created plan)", out.PlanVersion)
		}
	})
}

func TestListExerciseExecutions_ReflectsCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		plan := createPlanDirect(t, h, "listed", []exercise.PlanStep{minimalStep("a")}, nil)
		h.CreateExerciseExecution(httptest.NewRecorder(), exerciseExecutionReq(map[string]any{"plan_id": plan.ID, "name": "Run X"}))

		rec := httptest.NewRecorder()
		h.ListExerciseExecutions(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out []struct {
			Name string `json:"name"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 || out[0].Name != "Run X" {
			t.Fatalf("out = %+v, want 1 entry named Run X", out)
		}
	})
}

// TestGetExerciseExecution_IncludesSteps pins that GetExerciseExecution
// joins the execution with its step_executions (populated by
// LaunchExecution — internal/exercise's own state machine, not re-derived
// here).
func TestGetExerciseExecution_IncludesSteps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		plan := createPlanDirect(t, h, "with-steps", []exercise.PlanStep{minimalStep("a"), minimalStep("b", "a")}, nil)
		createRec := httptest.NewRecorder()
		h.CreateExerciseExecution(createRec, exerciseExecutionReq(map[string]any{"plan_id": plan.ID}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		launchRec := httptest.NewRecorder()
		h.LaunchExerciseExecution(launchRec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", created.ID))
		if launchRec.Code != http.StatusOK {
			t.Fatalf("launch: status = %d, body = %s", launchRec.Code, launchRec.Body.String())
		}

		rec := httptest.NewRecorder()
		h.GetExerciseExecution(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", created.ID))
		var out struct {
			Execution struct {
				Status string `json:"status"`
			} `json:"execution"`
			Steps []map[string]any `json:"steps"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Execution.Status != "running" {
			t.Errorf("execution.status = %q, want running", out.Execution.Status)
		}
		if len(out.Steps) != 2 {
			t.Fatalf("steps = %+v, want 2 (one per plan step)", out.Steps)
		}
	})
}

func TestLaunchExerciseExecution_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.LaunchExerciseExecution(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (LaunchExecution errors on an unknown execution id)", rec.Code)
		}
	})
}

// TestAbortExerciseExecution_CancelsPendingSteps pins the abort contract:
// pending/waiting steps flip to cancelled, and the execution itself flips
// to aborted.
func TestAbortExerciseExecution_CancelsPendingSteps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		plan := createPlanDirect(t, h, "abort-me", []exercise.PlanStep{minimalStep("a")}, nil)
		createRec := httptest.NewRecorder()
		h.CreateExerciseExecution(createRec, exerciseExecutionReq(map[string]any{"plan_id": plan.ID}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)
		h.LaunchExerciseExecution(httptest.NewRecorder(), withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", created.ID))

		rec := httptest.NewRecorder()
		h.AbortExerciseExecution(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", created.ID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var execStatus, stepStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM exercise_executions WHERE id=$1`, created.ID).Scan(&execStatus)
		pool.QueryRow(context.Background(), `SELECT status FROM exercise_step_executions WHERE execution_id=$1 AND step_id='a'`, created.ID).Scan(&stepStatus)
		if execStatus != "aborted" {
			t.Errorf("execution status = %q, want aborted", execStatus)
		}
		if stepStatus != "cancelled" {
			t.Errorf("step status = %q, want cancelled", stepStatus)
		}
	})
}

// TestApproveExerciseStep_CompletesStepAndRecordsEvidence pins the approval
// flow: the step flips to completed, an evidence entry is recorded, and the
// approver identity is captured.
func TestApproveExerciseStep_CompletesStepAndRecordsEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		approvalStep := exercise.PlanStep{ID: "a", Type: exercise.StepTypeApproval}
		plan := createPlanDirect(t, h, "needs-approval", []exercise.PlanStep{approvalStep}, nil)
		createRec := httptest.NewRecorder()
		h.CreateExerciseExecution(createRec, exerciseExecutionReq(map[string]any{"plan_id": plan.ID}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)
		h.LaunchExerciseExecution(httptest.NewRecorder(), withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", created.ID))

		uid := seedUser(t, pool, "aes-approver", "pw-Password1!", "admin", true)
		req := authedRequest(t, http.MethodPost, "/x", nil, "admin", uid)
		req = withURLParams(req, map[string]string{"id": created.ID, "stepId": "a"})
		rec := callAuthed(h.ApproveExerciseStep, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		evRec := httptest.NewRecorder()
		h.GetExerciseEvidence(evRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", created.ID))
		var evidence []struct {
			EvidenceType string `json:"evidence_type"`
			Actor        string `json:"actor"`
		}
		json.Unmarshal(evRec.Body.Bytes(), &evidence)
		var found bool
		for _, e := range evidence {
			if e.EvidenceType == "step_approved" && e.Actor == uid {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a step_approved evidence entry from %s, got %+v", uid, evidence)
		}
	})
}

// TestExerciseExecution_ExecutionPolicyPropagatesToBASDispatch proves the
// full async path: an operator-set ExecutionPolicy on a CreateExerciseExecution
// request survives persist → launch → the executor's poll loop → the
// AgentDispatchFn callback → dispatchRun's existing MaxPrivilege filter,
// landing exactly where every other launch path lands. The scenario's one
// step is admin-tier and the policy caps at user, so dispatchRun's existing
// all-filtered-completes-immediately behavior fires — no fake WS agent needed.
//
// This test builds its own Handler/Executor (rather than reusing
// exerciseHandler, which fixes a 1-hour poll interval and its own internal
// engine) because it needs a fast poll interval and a custom scenario
// registered under a specific ID.
func TestExerciseExecution_ExecutionPolicyPropagatesToBASDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		_, engine := minimalLiveScenario(t, "ee-execpolicy-sc", steps...)
		seedActiveAgent(t, pool, "ee-execpolicy-agent", "Windows")

		store := exercise.NewStore(pool)
		chain := exercise.NewEvidenceChain(store)
		reg := exercise.NewRegistry()
		exec := exercise.NewExecutor(store, chain, reg, exercise.NewPollScheduler(50*time.Millisecond), nil)
		exec.RegisterBuiltins(nil, nil, nil, nil)
		exec.RegisterBuiltinTriggers()
		h := New(pool, ws.NewHub(), engine, "").WithExercise(store, exec, chain)
		exec.Start()
		t.Cleanup(exec.Stop)

		planRec := httptest.NewRecorder()
		h.CreateExercisePlan(planRec, exercisePlanReq(map[string]any{
			"name": "Admin Only",
			"steps": []exercise.PlanStep{{
				ID: "at", Type: exercise.StepTypeAgentTask,
				Config: exercise.StepConfig{AgentTask: &exercise.AgentTaskConfig{
					AgentID: "ee-execpolicy-agent", ScenarioID: "ee-execpolicy-sc",
				}},
			}},
		}))
		var plan struct {
			ID string `json:"id"`
		}
		json.Unmarshal(planRec.Body.Bytes(), &plan)
		if plan.ID == "" {
			t.Fatalf("plan create failed: %s", planRec.Body.String())
		}

		execRec := httptest.NewRecorder()
		h.CreateExerciseExecution(execRec, exerciseExecutionReq(map[string]any{
			"plan_id": plan.ID, "name": "Run",
			"execution_policy": map[string]any{"maxPrivilege": "user"},
		}))
		var execOut struct {
			ID string `json:"id"`
		}
		json.Unmarshal(execRec.Body.Bytes(), &execOut)
		if execOut.ID == "" {
			t.Fatalf("execution create failed: %s", execRec.Body.String())
		}

		launchRec := httptest.NewRecorder()
		h.LaunchExerciseExecution(launchRec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", execOut.ID))
		if launchRec.Code != http.StatusOK {
			t.Fatalf("launch: status = %d, body = %s", launchRec.Code, launchRec.Body.String())
		}

		// Poll for the agent_task step to complete and yield a bas_run_id —
		// the poll scheduler's tick fires asynchronously.
		deadline := time.Now().Add(3 * time.Second)
		var runID string
		for time.Now().Before(deadline) {
			se, _ := store.GetStepExecByStepID(context.Background(), execOut.ID, "at")
			if se != nil && se.Status == exercise.StepCompleted {
				if v, ok := se.Result["bas_run_id"].(string); ok {
					runID = v
				}
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if runID == "" {
			t.Fatal("timed out waiting for the agent_task step to complete")
		}

		var status string
		var resultsJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT status, results FROM scenario_runs WHERE id=$1`, runID,
		).Scan(&status, &resultsJSON); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if status != "completed" {
			t.Fatalf("status = %q, want completed (all steps filtered by policy)", status)
		}
		var results []models.SimulationResult
		json.Unmarshal(resultsJSON, &results)
		if len(results) != 1 || results[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("results = %+v, want exactly 1 policy-privilege skip", results)
		}
	})
}
