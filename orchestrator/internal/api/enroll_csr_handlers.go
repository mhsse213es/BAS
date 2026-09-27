// orchestrator/internal/api/enroll_csr_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// enrollCSRRequest is the wire shape agent/protocol's SubmitCSR (Task 9)
// sends to POST /api/agents/enroll-csr.
type enrollCSRRequest struct {
	AgentID string `json:"agentId"`
	CSRPEM  string `json:"csrPem"`
}

// enrollCSRResponse carries only the signed certificate -- never a private
// key, per the spec's explicit invariant that the private key never
// crosses the enrollment boundary.
type enrollCSRResponse struct {
	CertPEM   string `json:"certPem"`
	CAPEM     string `json:"caPem"`
	ExpiresAt string `json:"expiresAt"`
}

// EnrollCSR handles POST /api/agents/enroll-csr — the bootstrap endpoint
// served on the TLS-server-only, NoClientCert :9444 listener (Task 7).
// Validates the shared bootstrap secret (same X-Agent-Token check as the
// legacy /api/agents/enroll), rejects re-bootstrap for an AgentID that
// already holds a valid unexpired certificate, then signs and returns a
// new client certificate via the deployment CA.
func (h *Handler) EnrollCSR(w http.ResponseWriter, r *http.Request) {
	if h.pki == nil {
		jsonError(w, "PKI not configured on this deployment", http.StatusServiceUnavailable)
		return
	}
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	var req enrollCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" || req.CSRPEM == "" {
		jsonError(w, "invalid request — agentId and csrPem required", http.StatusBadRequest)
		return
	}

	var alreadyValid bool
	err := h.db.QueryRow(r.Context(), `
		SELECT EXISTS (
			SELECT 1 FROM agent_certificates
			 WHERE agent_id = $1 AND revoked = false AND expires_at > NOW()
		)`, req.AgentID).Scan(&alreadyValid)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if alreadyValid {
		jsonError(w, "agent already holds a valid certificate — renew via mTLS instead of re-bootstrapping", http.StatusConflict)
		return
	}

	issued, err := h.pki.IssueClientCertificate(req.AgentID, []byte(req.CSRPEM))
	if err != nil {
		jsonError(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err = h.db.Exec(r.Context(), `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at)
		VALUES ($1, $2, NOW(), $3)`,
		issued.SerialNumber, req.AgentID, issued.ExpiresAt,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respond(w, enrollCSRResponse{
		CertPEM:   string(issued.CertPEM),
		CAPEM:     string(h.pki.RootCertPEM()),
		ExpiresAt: issued.ExpiresAt.Format(time.RFC3339),
	})
}
