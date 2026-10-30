package api

import (
	"net/http"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/findings"
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

	respond(w, findings.GroupByEndpoint(agents, open, requested))
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
