package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/exercise"
	"github.com/jackc/pgx/v5/pgxpool"
)

func exerciseTemplateReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/exercises/templates", bytes.NewReader(b))
}

func TestListExerciseTemplates_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListExerciseTemplates(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out []exercise.Template
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("expected 0 templates, got %d", len(out))
		}
	})
}

func TestGetExerciseTemplate_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetExerciseTemplate(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestCreateExerciseTemplate_MissingName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateExerciseTemplate(rec, exerciseTemplateReq(map[string]any{"steps": []exercise.PlanStep{minimalStep("a")}}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateExerciseTemplate_InvalidGraphReturns200WithErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateExerciseTemplate(rec, exerciseTemplateReq(map[string]any{
			"name": "Broken", "steps": []exercise.PlanStep{minimalStep("a", "a")},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (validation errors, not an HTTP error)", rec.Code)
		}
		var out struct {
			Valid bool `json:"valid"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Valid {
			t.Fatal("expected a self-loop template graph to be invalid")
		}
	})
}

func TestCreateExerciseTemplate_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateExerciseTemplate(rec, exerciseTemplateReq(map[string]any{
			"name": "Phishing 101", "category": "phishing", "steps": []exercise.PlanStep{minimalStep("a")},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out exercise.Template
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.ID == "" || out.BuiltIn {
			t.Fatalf("out = %+v, want a generated ID and built_in=false", out)
		}

		getRec := httptest.NewRecorder()
		h.GetExerciseTemplate(getRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", out.ID))
		if getRec.Code != http.StatusOK {
			t.Fatalf("get after create: status = %d, want 200", getRec.Code)
		}
	})
}

// TestCreateExerciseTemplate_NameLengthCollisionOverwrites characterizes a
// real bug in CreateExerciseTemplate (exercise_handlers.go): when no ID is
// supplied it generates one as "custom-"+len(name) (the code's own comment
// calls this "crude; real ID from DB gen"). Two templates whose names share
// the same length collide onto the same generated ID, and since
// UpsertTemplate is an ON CONFLICT (id) DO UPDATE, the second silently
// overwrites the first instead of creating a separate template. Flagged,
// not fixed, per the "flag unrelated bugs, don't fix without asking" policy.
func TestCreateExerciseTemplate_NameLengthCollisionOverwrites(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		first := httptest.NewRecorder()
		h.CreateExerciseTemplate(first, exerciseTemplateReq(map[string]any{
			"name": "AAAAA", "steps": []exercise.PlanStep{minimalStep("a")},
		}))
		var firstOut exercise.Template
		json.Unmarshal(first.Body.Bytes(), &firstOut)

		second := httptest.NewRecorder()
		h.CreateExerciseTemplate(second, exerciseTemplateReq(map[string]any{
			"name": "BBBBB", "steps": []exercise.PlanStep{minimalStep("a")}, // same length as "AAAAA"
		}))
		var secondOut exercise.Template
		json.Unmarshal(second.Body.Bytes(), &secondOut)

		if firstOut.ID != secondOut.ID {
			t.Fatalf("expected the length-based ID scheme to collide (got distinct IDs %q and %q) — bug may already be fixed, update this test", firstOut.ID, secondOut.ID)
		}

		listRec := httptest.NewRecorder()
		h.ListExerciseTemplates(listRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var list []exercise.Template
		json.Unmarshal(listRec.Body.Bytes(), &list)
		if len(list) != 1 || list[0].Name != "BBBBB" {
			t.Fatalf("list = %+v, want exactly 1 template named BBBBB (AAAAA silently overwritten)", list)
		}
	})
}

func TestInstantiateExerciseTemplate_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.InstantiateExerciseTemplate(rec, withURLParam(exerciseTemplateReq(map[string]any{}), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestInstantiateExerciseTemplate_MissingRequiredVariable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateExerciseTemplate(createRec, exerciseTemplateReq(map[string]any{
			"name": "needs-var", "steps": []exercise.PlanStep{minimalStep("a")},
			"variables": []exercise.VarDef{{Name: "TargetDomain", Required: true}},
		}))
		var tmpl exercise.Template
		json.Unmarshal(createRec.Body.Bytes(), &tmpl)

		rec := httptest.NewRecorder()
		h.InstantiateExerciseTemplate(rec, withURLParam(exerciseTemplateReq(map[string]any{}), "id", tmpl.ID))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestInstantiateExerciseTemplate_Success pins the full snapshot contract:
// instantiating a template creates both a Plan (a durable snapshot of the
// template's step graph, decoupled from later template edits) and an
// Execution bound to it.
func TestInstantiateExerciseTemplate_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateExerciseTemplate(createRec, exerciseTemplateReq(map[string]any{
			"name": "instantiate-me", "steps": []exercise.PlanStep{minimalStep("a")},
		}))
		var tmpl exercise.Template
		json.Unmarshal(createRec.Body.Bytes(), &tmpl)

		rec := httptest.NewRecorder()
		h.InstantiateExerciseTemplate(rec, withURLParam(exerciseTemplateReq(map[string]any{
			"name": "My Drill", "targets": []exercise.Target{{ID: "t1", Name: "Bob"}},
		}), "id", tmpl.ID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Plan struct {
				ID         string `json:"id"`
				TemplateID string `json:"template_id"`
			} `json:"plan"`
			Execution struct {
				ID     string `json:"id"`
				PlanID string `json:"plan_id"`
				Name   string `json:"name"`
			} `json:"execution"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Plan.ID == "" || out.Plan.TemplateID != tmpl.ID {
			t.Fatalf("plan = %+v, want a new plan snapshotting template_id %q", out.Plan, tmpl.ID)
		}
		if out.Execution.PlanID != out.Plan.ID || out.Execution.Name != "My Drill" {
			t.Fatalf("execution = %+v, want plan_id %q and name My Drill", out.Execution, out.Plan.ID)
		}
	})
}
