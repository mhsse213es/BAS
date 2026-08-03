package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/remediation"
)

// GET /api/technique-verification-runs/{id}
func (h *Handler) GetTechniqueVerification(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var run remediation.TechniqueVerificationRun
	err := h.db.QueryRow(r.Context(),
		`SELECT id, request_id, agent_id, check_id, technique_id, engine, run_id, status, reason,
		        requested_by, requested_at, dispatched_at, completed_at
		   FROM technique_verification_runs WHERE id=$1`, id,
	).Scan(&run.ID, &run.RequestID, &run.AgentID, &run.CheckID, &run.TechniqueID, &run.Engine, &run.RunID,
		&run.Status, &run.Reason, &run.RequestedBy, &run.RequestedAt, &run.DispatchedAt, &run.CompletedAt)
	if err != nil {
		jsonError(w, "technique verification not found", http.StatusNotFound)
		return
	}
	respond(w, run)
}
