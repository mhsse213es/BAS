package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/remediation"
)

// scanRemediationRequest reads one remediation_requests row into a
// remediation.RemediationRequest, the shared read path for GetRemediation,
// CancelRemediation, and RollbackRemediation.
func (h *Handler) scanRemediationRequest(ctx context.Context, id string) (remediation.RemediationRequest, error) {
	var req remediation.RemediationRequest
	var tier int
	err := h.db.QueryRow(ctx,
		`SELECT id, remediation_id, agent_id, check_id, tier, status, fix_run_id, verify_run_id, error,
		        requested_by, approved_by, reason, rollback_available, rollback_status, rollback_run_id,
		        rollback_verify_run_id, requested_at, dispatched_at, execution_completed_at,
		        verification_completed_at, completed_at
		   FROM remediation_requests WHERE id=$1`, id,
	).Scan(&req.ID, &req.RemediationID, &req.AgentID, &req.CheckID, &tier, &req.Status, &req.FixRunID, &req.VerifyRunID,
		&req.Error, &req.RequestedBy, &req.ApprovedBy, &req.Reason, &req.RollbackAvailable, &req.RollbackStatus,
		&req.RollbackRunID, &req.RollbackVerifyRunID, &req.RequestedAt, &req.DispatchedAt, &req.ExecutionCompletedAt,
		&req.VerificationCompletedAt, &req.CompletedAt)
	req.Tier = remediation.Tier(tier)
	return req, err
}

// reapTimedOutRemediation marks req as StatusTimedOut if it's been sitting
// in a non-terminal, dispatched-or-later status past its deadline (catalog
// EstimatedTimeSec x 4, floor 60s) -- checked lazily whenever a
// remediation is read, the same on-read pattern
// internal/api/liveness.go's runIsStale uses for scenario_runs, rather
// than a background sweep.
func (h *Handler) reapTimedOutRemediation(ctx context.Context, req *remediation.RemediationRequest) {
	if req.Status != remediation.StatusDispatched && req.Status != remediation.StatusRunning && req.Status != remediation.StatusVerifying {
		return
	}
	if req.DispatchedAt == nil {
		return
	}
	deadline := 60 * time.Second
	if h.remediationCatalog != nil {
		if entry, ok := h.remediationCatalog.ByID(req.RemediationID); ok && entry.EstimatedTimeSec > 0 {
			d := time.Duration(entry.EstimatedTimeSec*4) * time.Second
			if d > deadline {
				deadline = d
			}
		}
	}
	if time.Since(*req.DispatchedAt) <= deadline {
		return
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1 WHERE id=$2 AND status=$3`,
		remediation.StatusTimedOut, req.ID, req.Status)
	req.Status = remediation.StatusTimedOut
}

// GET /api/remediation-requests/{requestId}
func (h *Handler) GetRemediation(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.scanRemediationRequest(r.Context(), requestID)
	if err != nil {
		jsonError(w, "remediation request not found", http.StatusNotFound)
		return
	}
	h.reapTimedOutRemediation(r.Context(), &req)
	respond(w, req)
}

// GET /api/agents/{agentId}/remediations
func (h *Handler) ListAgentRemediations(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	rows, err := h.db.Query(r.Context(),
		`SELECT id, remediation_id, agent_id, check_id, tier, status, fix_run_id, verify_run_id, error,
		        requested_by, approved_by, reason, rollback_available, rollback_status, rollback_run_id,
		        rollback_verify_run_id, requested_at, dispatched_at, execution_completed_at,
		        verification_completed_at, completed_at
		   FROM remediation_requests WHERE agent_id=$1 ORDER BY requested_at DESC LIMIT 100`, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []remediation.RemediationRequest{}
	for rows.Next() {
		var req remediation.RemediationRequest
		var tier int
		if err := rows.Scan(&req.ID, &req.RemediationID, &req.AgentID, &req.CheckID, &tier, &req.Status, &req.FixRunID,
			&req.VerifyRunID, &req.Error, &req.RequestedBy, &req.ApprovedBy, &req.Reason, &req.RollbackAvailable,
			&req.RollbackStatus, &req.RollbackRunID, &req.RollbackVerifyRunID, &req.RequestedAt, &req.DispatchedAt,
			&req.ExecutionCompletedAt, &req.VerificationCompletedAt, &req.CompletedAt); err != nil {
			continue
		}
		req.Tier = remediation.Tier(tier)
		out = append(out, req)
	}
	respond(w, map[string]any{"remediations": out})
}
