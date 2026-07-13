package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/exercise"
	"github.com/jackc/pgx/v5/pgxpool"
)

// launchedExecution creates a plan+execution and launches it, returning the
// execution ID. Shared setup for evidence/events tests, which need a running
// execution to attach evidence/events to.
func launchedExecution(t *testing.T, h *Handler, steps []exercise.PlanStep) string {
	t.Helper()
	plan := createPlanDirect(t, h, "evidence-fixture", steps, nil)
	createRec := httptest.NewRecorder()
	h.CreateExerciseExecution(createRec, exerciseExecutionReq(map[string]any{"plan_id": plan.ID}))
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(createRec.Body.Bytes(), &created)
	h.LaunchExerciseExecution(httptest.NewRecorder(), withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", created.ID))
	return created.ID
}

func TestGetExerciseEvidence_EmptyThenPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})

		rec := httptest.NewRecorder()
		h.GetExerciseEvidence(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		var empty []exercise.Evidence
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 evidence entries before any step activity, got %d", len(empty))
		}

		body, _ := json.Marshal(map[string]any{
			"evidence_type": "manual_note", "source": "operator", "payload": map[string]any{"note": "SOC paged"},
		})
		injectRec := httptest.NewRecorder()
		h.InjectEvidence(injectRec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "id", execID))
		if injectRec.Code != http.StatusOK {
			t.Fatalf("inject: status = %d, want 200, body = %s", injectRec.Code, injectRec.Body.String())
		}

		rec2 := httptest.NewRecorder()
		h.GetExerciseEvidence(rec2, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		var out []exercise.Evidence
		json.Unmarshal(rec2.Body.Bytes(), &out)
		if len(out) != 1 || out[0].EvidenceType != "manual_note" {
			t.Fatalf("out = %+v, want 1 manual_note entry", out)
		}
	})
}

func TestInjectEvidence_MissingType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]any{"source": "operator"})
		h.InjectEvidence(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "id", execID))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestInjectEvidence_DefaultsActorFromClaims pins that an empty actor in the
// request body falls back to the authenticated caller, matching
// CreateExercisePlan's created_by behavior.
func TestInjectEvidence_DefaultsActorFromClaims(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})
		uid := seedUser(t, pool, "ie-actor", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"evidence_type": "ticket_created"})
		req := authedRequest(t, http.MethodPost, "/x", bytes.NewReader(body), "admin", uid)
		req = withURLParam(req, "id", execID)
		rec := callAuthed(h.InjectEvidence, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out exercise.Evidence
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Actor != uid {
			t.Fatalf("actor = %q, want %q", out.Actor, uid)
		}
	})
}

func TestVerifyExerciseChain_IntactAfterEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})
		body, _ := json.Marshal(map[string]any{"evidence_type": "manual_note"})
		h.InjectEvidence(httptest.NewRecorder(), withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "id", execID))

		rec := httptest.NewRecorder()
		h.VerifyExerciseChain(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestVerifyExerciseChain_DetectsTamper pins the tamper-evident contract:
// mutating a stored evidence payload after the fact breaks the hash chain,
// and VerifyExerciseChain reports 409 rather than 200.
func TestVerifyExerciseChain_DetectsTamper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})
		body, _ := json.Marshal(map[string]any{"evidence_type": "manual_note", "payload": map[string]any{"note": "original"}})
		h.InjectEvidence(httptest.NewRecorder(), withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "id", execID))

		_, err := pool.Exec(context.Background(),
			`UPDATE exercise_evidence SET payload_json='{"note":"tampered"}' WHERE execution_id=$1`, execID)
		if err != nil {
			t.Fatalf("tamper update: %v", err)
		}

		rec := httptest.NewRecorder()
		h.VerifyExerciseChain(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (tampered chain)", rec.Code)
		}
	})
}

func TestGetExerciseEvents_ReflectsLaunchAndApprove(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{{ID: "a", Type: exercise.StepTypeApproval}})

		uid := seedUser(t, pool, "gee-approver", "pw-Password1!", "admin", true)
		req := authedRequest(t, http.MethodPost, "/x", nil, "admin", uid)
		req = withURLParams(req, map[string]string{"id": execID, "stepId": "a"})
		callAuthed(h.ApproveExerciseStep, req)

		rec := httptest.NewRecorder()
		h.GetExerciseEvents(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) < 2 {
			t.Fatalf("expected at least 2 events (started, approved), got %+v", out)
		}
	})
}
