package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
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
	if h.exerciseStore == nil {
		respond(w, []exercise.Plan{})
		return
	}
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
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	p, err := h.exerciseStore.GetPlan(r.Context(), id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	respond(w, p)
}

func (h *Handler) CreateExercisePlan(w http.ResponseWriter, r *http.Request) {
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
	var p exercise.Plan
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	if errs := exercise.ValidatePlan(&p); len(errs) > 0 {
		respond(w, map[string]any{"valid": false, "errors": errs})
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

// POST /api/exercises/plans/{id}/validate
// Returns validation results without saving. Frontend DAG editor calls this.
func (h *Handler) ValidateExercisePlan(w http.ResponseWriter, r *http.Request) {
	var p exercise.Plan
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	errs := exercise.ValidatePlan(&p)
	respond(w, map[string]any{"valid": len(errs) == 0, "errors": errs})
}

func (h *Handler) UpdateExercisePlan(w http.ResponseWriter, r *http.Request) {
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
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
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
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
	if h.exerciseStore == nil {
		respond(w, []exercise.Execution{})
		return
	}
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
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
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
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		PlanID          string                   `json:"plan_id"`
		Name            string                   `json:"name"`
		Targets         []exercise.Target        `json:"targets"`
		Variables       map[string]string        `json:"variables"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"execution_policy,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlanID == "" {
		jsonError(w, "plan_id required", http.StatusBadRequest)
		return
	}
	plan, err := h.exerciseStore.GetPlan(r.Context(), req.PlanID)
	if err != nil {
		jsonError(w, "plan not found", http.StatusNotFound)
		return
	}
	// Validate required variables are supplied before creating the execution.
	if verr := exercise.ValidateVars(plan.Variables, req.Variables); verr != nil {
		jsonError(w, verr.Error(), http.StatusUnprocessableEntity)
		return
	}
	ex := &exercise.Execution{
		PlanID:          req.PlanID,
		Name:            req.Name,
		Status:          exercise.ExecDraft,
		InitiatedBy:     actorID(r),
		Targets:         req.Targets,
		Variables:       req.Variables,
		PlanVersion:     plan.Version,
		ExecutionPolicy: req.ExecutionPolicy,
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
	if h.exerciseExecutor == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
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
	if h.exerciseExecutor == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
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
	if h.exerciseExecutor == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
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
	if h.exerciseStore == nil {
		respond(w, []exercise.Evidence{})
		return
	}
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
	if h.exerciseChain == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.exerciseChain.Verify(r.Context(), id); err != nil {
		jsonError(w, "chain verification failed: "+err.Error(), http.StatusConflict)
		return
	}
	respond(w, map[string]string{"status": "ok", "chain": "intact"})
}

// GET /api/exercises/executions/{id}/events
func (h *Handler) GetExerciseEvents(w http.ResponseWriter, r *http.Request) {
	if h.exerciseStore == nil {
		respond(w, []map[string]interface{}{})
		return
	}
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

// ── Templates ─────────────────────────────────────────────────────────────────

// GET /api/exercises/templates
func (h *Handler) ListExerciseTemplates(w http.ResponseWriter, r *http.Request) {
	if h.exerciseStore == nil {
		respond(w, []exercise.Template{})
		return
	}
	tmps, err := h.exerciseStore.ListTemplates(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tmps == nil {
		tmps = []exercise.Template{}
	}
	respond(w, tmps)
}

// GET /api/exercises/templates/{id}
func (h *Handler) GetExerciseTemplate(w http.ResponseWriter, r *http.Request) {
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	t, err := h.exerciseStore.GetTemplate(r.Context(), id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	respond(w, t)
}

// POST /api/exercises/templates (Admin)
func (h *Handler) CreateExerciseTemplate(w http.ResponseWriter, r *http.Request) {
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
	var t exercise.Template
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if t.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	// Validate the embedded plan graph.
	p := &exercise.Plan{Steps: t.Steps, Variables: t.Variables}
	if errs := exercise.ValidatePlan(p); len(errs) > 0 {
		respond(w, map[string]any{"valid": false, "errors": errs})
		return
	}
	t.BuiltIn = false
	t.Author = actorID(r)
	if t.ID == "" {
		t.ID = "custom-" + newID()
	}
	if err := h.exerciseStore.UpsertTemplate(r.Context(), &t); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.template.create", t.ID, map[string]any{"name": t.Name}, "success")
	respond(w, t)
}

// POST /api/exercises/templates/{id}/instantiate
// Creates a Plan + Execution from a template with operator-provided variables.
func (h *Handler) InstantiateExerciseTemplate(w http.ResponseWriter, r *http.Request) {
	if h.exerciseStore == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Name      string            `json:"name"`
		Targets   []exercise.Target `json:"targets"`
		Variables map[string]string `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	tmpl, err := h.exerciseStore.GetTemplate(r.Context(), id)
	if err != nil {
		jsonError(w, "template not found", http.StatusNotFound)
		return
	}
	// Validate required variables.
	if verr := exercise.ValidateVars(tmpl.Variables, req.Variables); verr != nil {
		jsonError(w, verr.Error(), http.StatusUnprocessableEntity)
		return
	}
	if req.Name == "" {
		req.Name = tmpl.Name
	}
	// Create a Plan snapshot from the template (preserves step graph + var defs).
	plan := &exercise.Plan{
		Name:        req.Name,
		Description: tmpl.Description,
		Steps:       tmpl.Steps,
		Variables:   tmpl.Variables,
		TemplateID:  tmpl.ID,
		Version:     tmpl.Version,
		CreatedBy:   actorID(r),
	}
	if err := h.exerciseStore.CreatePlan(r.Context(), plan); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Create the Execution bound to that Plan with the provided variables.
	ex := &exercise.Execution{
		PlanID:      plan.ID,
		Name:        req.Name,
		Status:      exercise.ExecDraft,
		InitiatedBy: actorID(r),
		Targets:     req.Targets,
		Variables:   req.Variables,
		PlanVersion: plan.Version,
	}
	if err := h.exerciseStore.CreateExecution(r.Context(), ex); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.template.instantiate", tmpl.ID,
		map[string]any{"template": tmpl.Name, "execution_id": ex.ID}, "success")
	respond(w, map[string]any{"plan": plan, "execution": ex})
}

// ── Report exports ────────────────────────────────────────────────────────────

// buildExerciseReport assembles all data for one execution into a report struct.
func (h *Handler) buildExerciseReport(r *http.Request, id string) (*reporting.ExerciseReport, error) {
	if h.exerciseStore == nil || h.exerciseChain == nil {
		return nil, fmt.Errorf("exercise engine not loaded")
	}
	ctx := r.Context()
	ex, err := h.exerciseStore.GetExecution(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("execution not found: %w", err)
	}
	plan, err := h.exerciseStore.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return nil, fmt.Errorf("plan not found: %w", err)
	}
	steps, _ := h.exerciseStore.ListStepExecutions(ctx, id)
	evidence, _ := h.exerciseStore.ListEvidence(ctx, id)
	events, _ := h.exerciseStore.ListEvents(ctx, id)
	chainErr := ""
	chainOK := true
	if err := h.exerciseChain.Verify(ctx, id); err != nil {
		chainOK = false
		chainErr = err.Error()
	}
	rep := &reporting.ExerciseReport{
		Execution: ex,
		Plan:      plan,
		Steps:     steps,
		Evidence:  evidence,
		Events:    events,
		Score:     ex.Score,
		ChainOK:   chainOK,
		ChainErr:  chainErr,
	}
	rep.Timeline = reporting.BuildTimeline(rep)
	return rep, nil
}

// GET /api/exercises/executions/{id}/report.json
func (h *Handler) GetExerciseReportJSON(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rep, err := h.buildExerciseReport(r, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeBufferedReport(w, "application/json",
		fmt.Sprintf(`attachment; filename="%s"`, buildReportFilename("Exercise_Report", id, "json")),
		"exercise report json",
		func(out io.Writer) error { return reporting.ExerciseReportJSON(out, rep) })
}

// GET /api/exercises/executions/{id}/report.html
func (h *Handler) GetExerciseReportHTML(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rep, err := h.buildExerciseReport(r, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "exercise report html",
		func(out io.Writer) error { return reporting.ExerciseReportHTML(out, rep) })
}

// GET /api/exercises/executions/{id}/report.pdf
func (h *Handler) GetExerciseReportPDF(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rep, err := h.buildExerciseReport(r, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeBufferedReport(w, "application/pdf",
		fmt.Sprintf(`inline; filename="%s"`, buildReportFilename("Exercise_Report", id, "pdf")),
		"exercise report pdf",
		func(out io.Writer) error { return reporting.ExerciseReportPDF(r.Context(), out, rep) })
}

// GET /api/exercises/executions/{id}/report.csv
func (h *Handler) GetExerciseReportCSV(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rep, err := h.buildExerciseReport(r, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeBufferedReport(w, "text/csv",
		fmt.Sprintf(`attachment; filename="%s"`, buildReportFilename("Exercise_Report", id, "csv")),
		"exercise report csv",
		func(out io.Writer) error { return reporting.ExerciseReportCSV(out, rep) })
}

// POST /api/exercises/executions/{id}/evidence
// Operator-injected evidence: SOC acknowledged, ticket created, exec notified, etc.
func (h *Handler) InjectEvidence(w http.ResponseWriter, r *http.Request) {
	if h.exerciseChain == nil {
		jsonError(w, "exercise engine not loaded", http.StatusServiceUnavailable)
		return
	}
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
