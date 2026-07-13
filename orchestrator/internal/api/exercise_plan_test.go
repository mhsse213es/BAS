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
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// exerciseHandler wires a real exercise.Store/Executor/EvidenceChain — every
// exercise handler dereferences these unconditionally (no nil-guard, unlike
// reportingEngine/complianceMapper/ticketing), so production always wires
// them and tests do too, matching cmd/server's own construction.
func exerciseHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	store := exercise.NewStore(pool)
	chain := exercise.NewEvidenceChain(store)
	reg := exercise.NewRegistry()
	exec := exercise.NewExecutor(store, chain, reg, exercise.NewPollScheduler(time.Hour), nil)
	exec.RegisterBuiltins(nil)
	exec.RegisterBuiltinTriggers()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithExercise(store, exec, chain)
}

// minimalStep returns the simplest valid PlanStep (notify — no config
// required, no side effects) so plan fixtures aren't coupled to any one
// step type's own already-tested behavior.
func minimalStep(id string, dependsOn ...string) exercise.PlanStep {
	return exercise.PlanStep{ID: id, Type: exercise.StepTypeNotify, DependsOn: dependsOn}
}

func exercisePlanReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/exercises/plans", bytes.NewReader(b))
}

func TestListExercisePlans_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListExercisePlans(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var empty []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 plans, got %d", len(empty))
		}

		createRec := httptest.NewRecorder()
		h.CreateExercisePlan(createRec, exercisePlanReq(map[string]any{
			"name": "Phishing Drill", "steps": []exercise.PlanStep{minimalStep("a")},
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create: status = %d, want 200, body = %s", createRec.Code, createRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListExercisePlans(listRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Phishing Drill" {
			t.Fatalf("out = %+v, want 1 entry named Phishing Drill", out)
		}
	})
}

func TestGetExercisePlan_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetExercisePlan(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestCreateExercisePlan_MissingName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateExercisePlan(rec, exercisePlanReq(map[string]any{"steps": []exercise.PlanStep{minimalStep("a")}}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateExercisePlan_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte(`{"name":`)))
		rec := httptest.NewRecorder()
		h.CreateExercisePlan(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestCreateExercisePlan_InvalidGraphReturns200WithErrors pins that a plan
// failing exercise.ValidatePlan (already exhaustively tested at the package
// level — cycles, missing deps, duplicate IDs, etc.) is NOT a 400: the
// handler responds 200 with {valid:false, errors:[...]} so the frontend DAG
// editor can render inline validation feedback, and does not persist it.
func TestCreateExercisePlan_InvalidGraphReturns200WithErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateExercisePlan(rec, exercisePlanReq(map[string]any{
			"name": "Broken", "steps": []exercise.PlanStep{minimalStep("a", "a")}, // self-loop
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (validation errors, not an HTTP error)", rec.Code)
		}
		var out struct {
			Valid  bool     `json:"valid"`
			Errors []string `json:"errors"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Valid || len(out.Errors) == 0 {
			t.Fatalf("out = %+v, want valid:false with errors", out)
		}

		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM exercise_plans`).Scan(&n)
		if n != 0 {
			t.Fatalf("invalid plan should not persist, found %d rows", n)
		}
	})
}

// TestCreateExercisePlan_StampsCreatedByFromClaims pins that created_by comes
// from the authenticated caller, not the request body.
func TestCreateExercisePlan_StampsCreatedByFromClaims(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		uid := seedUser(t, pool, "cep-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"name": "x", "steps": []exercise.PlanStep{minimalStep("a")}})
		req := authedRequest(t, http.MethodPost, "/api/exercises/plans", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateExercisePlan, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			CreatedBy string `json:"created_by"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.CreatedBy != uid {
			t.Fatalf("created_by = %q, want %q", out.CreatedBy, uid)
		}
	})
}

func TestValidateExercisePlan_ValidAndInvalid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)

		okRec := httptest.NewRecorder()
		h.ValidateExercisePlan(okRec, exercisePlanReq(map[string]any{"steps": []exercise.PlanStep{minimalStep("a")}}))
		var okOut struct {
			Valid bool `json:"valid"`
		}
		json.Unmarshal(okRec.Body.Bytes(), &okOut)
		if !okOut.Valid {
			t.Errorf("expected a valid single-step plan to validate, body = %s", okRec.Body.String())
		}

		badRec := httptest.NewRecorder()
		h.ValidateExercisePlan(badRec, exercisePlanReq(map[string]any{"steps": []exercise.PlanStep{minimalStep("a", "a")}}))
		var badOut struct {
			Valid bool `json:"valid"`
		}
		json.Unmarshal(badRec.Body.Bytes(), &badOut)
		if badOut.Valid {
			t.Error("expected a self-loop plan to be invalid")
		}

		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM exercise_plans`).Scan(&n)
		if n != 0 {
			t.Fatalf("ValidateExercisePlan must never persist, found %d rows", n)
		}
	})
}

func TestUpdateExercisePlan_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateExercisePlan(createRec, exercisePlanReq(map[string]any{
			"name": "v1", "steps": []exercise.PlanStep{minimalStep("a")},
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{"name": "v2", "steps": []exercise.PlanStep{minimalStep("a")}})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateExercisePlan(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		getRec := httptest.NewRecorder()
		h.GetExercisePlan(getRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", created.ID))
		var out struct {
			Name string `json:"name"`
		}
		json.Unmarshal(getRec.Body.Bytes(), &out)
		if out.Name != "v2" {
			t.Fatalf("name after update = %q, want v2", out.Name)
		}
	})
}

func TestDeleteExercisePlan_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateExercisePlan(createRec, exercisePlanReq(map[string]any{
			"name": "to-delete", "steps": []exercise.PlanStep{minimalStep("a")},
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteExercisePlan(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", delRec.Code)
		}

		getRec := httptest.NewRecorder()
		h.GetExercisePlan(getRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", created.ID))
		if getRec.Code != http.StatusNotFound {
			t.Fatalf("status after delete = %d, want 404", getRec.Code)
		}
	})
}
