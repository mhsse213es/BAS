package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/exercise"
)

// actorID extracts the authenticated username from the JWT context.
func actorID(r *http.Request) string {
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		return claims.UserID
	}
	return ""
}

// ── Exercise Plan CRUD ────────────────────────────────────────────────────────

func (h *Handler) ListExercisePlans(w http.ResponseWriter, r *http.Request) {
	plans, err := h.exerciseStore.ListPlans(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if plans == nil {
		plans = []exercise.Plan{}
	}
	respond(w, plans)
}

func (h *Handler) GetExercisePlan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, err := h.exerciseStore.GetPlan(r.Context(), id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	respond(w, p)
}

func (h *Handler) CreateExercisePlan(w http.ResponseWriter, r *http.Request) {
	var p exercise.Plan
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	p.CreatedBy = actorID(r)
	if err := h.exerciseStore.CreatePlan(r.Context(), &p); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.plan.create", p.ID, map[string]any{"name": p.Name}, "success")
	respond(w, p)
}

func (h *Handler) UpdateExercisePlan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var p exercise.Plan
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	p.ID = id
	if err := h.exerciseStore.UpdatePlan(r.Context(), &p); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.plan.update", id, nil, "success")
	respond(w, p)
}

func (h *Handler) DeleteExercisePlan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.exerciseStore.DeletePlan(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.plan.delete", id, nil, "success")
	respond(w, map[string]string{"status": "deleted"})
}

// ── Exercise Executions ───────────────────────────────────────────────────────

func (h *Handler) ListExerciseExecutions(w http.ResponseWriter, r *http.Request) {
	execs, err := h.exerciseStore.ListExecutions(r.Context(), 50)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if execs == nil {
		execs = []exercise.Execution{}
	}
	respond(w, execs)
}

func (h *Handler) GetExerciseExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ex, err := h.exerciseStore.GetExecution(r.Context(), id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	steps, _ := h.exerciseStore.ListStepExecutions(r.Context(), id)
	respond(w, map[string]interface{}{"execution": ex, "steps": steps})
}

func (h *Handler) CreateExerciseExecution(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID  string            `json:"plan_id"`
		Name    string            `json:"name"`
		Targets []exercise.Target `json:"targets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlanID == "" {
		jsonError(w, "plan_id required", http.StatusBadRequest)
		return
	}
	if _, err := h.exerciseStore.GetPlan(r.Context(), req.PlanID); err != nil {
		jsonError(w, "plan not found", http.StatusNotFound)
		return
	}
	ex := &exercise.Execution{
		PlanID:      req.PlanID,
		Name:        req.Name,
		Status:      exercise.ExecDraft,
		InitiatedBy: actorID(r),
		Targets:     req.Targets,
	}
	if err := h.exerciseStore.CreateExecution(r.Context(), ex); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.execution.create", ex.ID, map[string]any{"plan_id": req.PlanID}, "success")
	respond(w, ex)
}

// POST /api/exercises/executions/{id}/launch
func (h *Handler) LaunchExerciseExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.exerciseExecutor.LaunchExecution(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.execution.launch", id, nil, "success")
	respond(w, map[string]string{"status": "running"})
}

// POST /api/exercises/executions/{id}/abort
func (h *Handler) AbortExerciseExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.exerciseExecutor.AbortExecution(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.execution.abort", id, nil, "success")
	respond(w, map[string]string{"status": "aborted"})
}

// POST /api/exercises/executions/{id}/steps/{stepId}/approve
func (h *Handler) ApproveExerciseStep(w http.ResponseWriter, r *http.Request) {
	execID := chi.URLParam(r, "id")
	stepID := chi.URLParam(r, "stepId")
	approver := actorID(r)
	if err := h.exerciseExecutor.ApproveStep(r.Context(), execID, stepID, approver); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.step.approve", execID, map[string]any{"step_id": stepID, "approver": approver}, "success")
	respond(w, map[string]string{"status": "approved"})
}

// ── Evidence ──────────────────────────────────────────────────────────────────

// GET /api/exercises/executions/{id}/evidence
func (h *Handler) GetExerciseEvidence(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	evs, err := h.exerciseStore.ListEvidence(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if evs == nil {
		evs = []exercise.Evidence{}
	}
	respond(w, evs)
}

// GET /api/exercises/executions/{id}/evidence/verify
func (h *Handler) VerifyExerciseChain(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.exerciseChain.Verify(r.Context(), id); err != nil {
		jsonError(w, "chain verification failed: "+err.Error(), http.StatusConflict)
		return
	}
	respond(w, map[string]string{"status": "ok", "chain": "intact"})
}

// GET /api/exercises/executions/{id}/events
func (h *Handler) GetExerciseEvents(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	evs, err := h.exerciseStore.ListEvents(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if evs == nil {
		evs = []map[string]interface{}{}
	}
	respond(w, evs)
}

// POST /api/exercises/executions/{id}/evidence
// Operator-injected evidence: SOC acknowledged, ticket created, exec notified, etc.
func (h *Handler) InjectEvidence(w http.ResponseWriter, r *http.Request) {
	execID := chi.URLParam(r, "id")
	var req struct {
		EvidenceType string         `json:"evidence_type"`
		Actor        string         `json:"actor"`
		Source       string         `json:"source"`
		Payload      map[string]any `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.EvidenceType == "" {
		jsonError(w, "evidence_type required", http.StatusBadRequest)
		return
	}
	if req.Actor == "" {
		req.Actor = actorID(r)
	}
	ev, err := h.exerciseChain.Append(r.Context(), execID, "", req.EvidenceType, req.Actor, req.Source, req.Payload)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ev)
}
