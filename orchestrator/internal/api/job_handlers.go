package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/jobs/batch-remediation
// Same tier-gated permission logic as Sub-project 4's ExecuteRemediation --
// batch dispatch of a Tier 2 remediation to 50 machines is not a lesser
// action than dispatching it to one, so it gets no separate, weaker policy.
func (h *Handler) CreateBatchRemediationJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemediationID string   `json:"remediationId"`
		Reason        string   `json:"reason"`
		AgentIDs      []string `json:"agentIds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.RemediationID == "" {
		jsonError(w, "remediationId is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 {
		jsonError(w, "agentIds must contain at least one agent", http.StatusBadRequest)
		return
	}
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok {
		jsonError(w, "unknown remediationId", http.StatusNotFound)
		return
	}
	if entry.Tier == remediation.TierManualGuidance {
		jsonError(w, "this remediation is manual guidance only -- no automatic execution", http.StatusUnprocessableEntity)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	if entry.Tier == remediation.TierConfirmRequired && (claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation)) {
		jsonError(w, "this remediation requires an Administrator", http.StatusForbidden)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	payload, err := json.Marshal(map[string]string{"remediationId": entry.ID, "reason": req.Reason})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	job, err := h.jobsStore.CreateBatch(r.Context(), "batch_remediation", payload, actorID, req.AgentIDs)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.batch_remediation.create", job.ID,
		map[string]any{"remediationId": entry.ID, "agentCount": len(req.AgentIDs)}, "created")
	respond(w, map[string]any{"jobId": job.ID, "state": job.State, "targetCount": len(req.AgentIDs)})
}

// GET /api/jobs/{jobId}
func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	job, err := h.jobsStore.Get(r.Context(), jobID)
	if err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	targets, err := h.jobsStore.ListTargets(r.Context(), jobID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"job": job, "targets": targets})
}
