package api

import (
	"context"
	"net/http"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// ListRemediationsByEndpoint returns the endpoint-wise remediation view (Phase 1):
// one entry per endpoint, built from open findings, the agent table and the
// existing remediation requests. Access follows GET /api/remediations, which is
// the same findings-read permission. It does not read any execution status.
func (h *Handler) ListRemediationsByEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	agentRows, err := h.db.Query(ctx, `SELECT agent_id, hostname FROM agents`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var agents []findings.EndpointAgent
	for agentRows.Next() {
		var a findings.EndpointAgent
		if agentRows.Scan(&a.AgentID, &a.Hostname) == nil {
			agents = append(agents, a)
		}
	}
	agentRows.Close()

	findingRows, err := h.db.Query(ctx,
		`SELECT id, agent_id, technique_id, technique_name, tactic, severity, exposure_state, control_class
		   FROM findings WHERE status='open'`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var open []findings.EndpointFinding
	for findingRows.Next() {
		var f findings.EndpointFinding
		if findingRows.Scan(&f.ID, &f.AgentID, &f.TechniqueID, &f.TechniqueName, &f.Tactic,
			&f.Severity, &f.ExposureState, &f.ControlClass) == nil {
			f.Mitigations = mitigationNames(f.TechniqueID)
			open = append(open, f)
		}
	}
	findingRows.Close()

	reqRows, err := h.db.Query(ctx, `SELECT DISTINCT agent_id FROM remediation_requests`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	requested := map[string]bool{}
	for reqRows.Next() {
		var id string
		if reqRows.Scan(&id) == nil {
			requested[id] = true
		}
	}
	reqRows.Close()

	eps := findings.GroupByEndpoint(agents, open, requested)

	// Phase 2: request details (who requested, errors, run references) are shown
	// only to roles that can execute remediation. Others get the Phase 1 view.
	if claims, ok := auth.ClaimsFrom(ctx); ok && auth.HasPermission(claims.Role, auth.CanExecuteRemediation) {
		reqs, err := h.remediationRequestsForEndpoints(ctx)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		eps = findings.AttachRequests(eps, reqs)
	}
	respond(w, eps)
}

// remediationRequestsForEndpoints loads every remediation request with its latest
// independent verification run, newest first.
func (h *Handler) remediationRequestsForEndpoints(ctx context.Context) ([]findings.RemediationRequest, error) {
	rows, err := h.db.Query(ctx, `
		SELECT rr.id, rr.agent_id, rr.remediation_id, rr.check_id, rr.status, rr.error,
		       rr.requested_by, rr.requested_at, rr.completed_at, rr.fix_run_id, rr.verify_run_id,
		       COALESCE(tv.status, ''), COALESCE(tv.reason, ''), tv.completed_at
		  FROM remediation_requests rr
		  LEFT JOIN LATERAL (
		        SELECT status, reason, completed_at FROM technique_verification_runs t
		         WHERE t.request_id = rr.id ORDER BY t.requested_at DESC LIMIT 1
		  ) tv ON true
		 ORDER BY rr.requested_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findings.RemediationRequest
	for rows.Next() {
		var r findings.RemediationRequest
		if err := rows.Scan(&r.ID, &r.AgentID, &r.RemediationID, &r.CheckID, &r.Status, &r.Error,
			&r.RequestedBy, &r.RequestedAt, &r.CompletedAt, &r.FixRunID, &r.VerifyRunID,
			&r.VerificationStatus, &r.VerificationReason, &r.VerificationAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// mitigationNames returns the ATT&CK mitigation names for a technique, or nil when
// the technique is not in the ATT&CK data.
func mitigationNames(techniqueID string) []string {
	e := attackdata.Lookup(techniqueID)
	if e == nil {
		return nil
	}
	names := make([]string, 0, len(e.Mitigations))
	for _, m := range e.Mitigations {
		names = append(names, m.Name)
	}
	return names
}
