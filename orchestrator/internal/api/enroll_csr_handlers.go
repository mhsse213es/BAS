// orchestrator/internal/api/enroll_csr_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"regexp"
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

// agentIDPattern is the exact shape agent/identity.go produces:
// hex(SHA-256(hostname))[:16] -- 16 lowercase hex characters. The value is
// stamped verbatim into a signed certificate's CommonName and DNSNames SAN,
// so anything else is rejected before it can reach the CA.
var agentIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// EnrollCSR handles POST /api/agents/enroll-csr. It serves two distinct
// cases, distinguished by whether the request arrived with a verified mTLS
// client certificate (AuthenticatedAgentID, set by WithMTLSIdentity on the
// :9443 RequireAndVerifyClientCert listener only):
//
//   - Renewal (mTLS identity present): the handshake itself is the
//     authentication (spec Section 2 -- renewal never uses the bootstrap
//     secret). The claimed agentId must equal the certificate's identity,
//     and the "already holds a valid certificate" reuse check is skipped,
//     because holding a still-valid certificate is exactly what renewal
//     means. A certificate explicitly marked revoked cannot renew itself.
//
//   - Initial bootstrap (no mTLS identity -- the :9444 enrollment
//     listener): validates the shared bootstrap secret, then rejects the
//     request if this AgentID already holds a valid unexpired certificate.
//     The check and the INSERT run in one transaction serialized per
//     AgentID by a transaction-scoped advisory lock, so two concurrent
//     bootstraps for the same never-seen AgentID cannot both succeed.
func (h *Handler) EnrollCSR(w http.ResponseWriter, r *http.Request) {
	if h.pki == nil {
		jsonError(w, "PKI not configured on this deployment", http.StatusServiceUnavailable)
		return
	}
	mtlsID := AuthenticatedAgentID(r)
	if mtlsID == "" && !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	var req enrollCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" || req.CSRPEM == "" {
		jsonError(w, "invalid request — agentId and csrPem required", http.StatusBadRequest)
		return
	}
	if !agentIDPattern.MatchString(req.AgentID) {
		jsonError(w, "invalid agentId — expected 16 lowercase hex characters", http.StatusBadRequest)
		return
	}
	if mtlsID != "" && mtlsID != req.AgentID {
		// Same status and wording as wsAgentAuthorized (mtls_context.go): a
		// certificate issued for one agent must never obtain a certificate
		// for another identity.
		jsonError(w, "agentId does not match authenticated certificate", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Serialize every issuance for this AgentID (bootstrap and renewal
	// alike) until the transaction ends. A row lock (SELECT ... FOR UPDATE)
	// cannot do this: the race being closed is two requests for an AgentID
	// with NO rows yet, and there is nothing to lock. A partial unique index
	// cannot either: "valid" depends on expires_at > NOW(), which is not
	// immutable and so cannot appear in an index predicate, and renewal
	// legitimately creates a second valid row while the old one is still
	// unexpired.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('agent_certificates:' || $1, 0))`, req.AgentID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if mtlsID != "" {
		serial := r.TLS.PeerCertificates[0].SerialNumber.Text(16)
		var revoked bool
		err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM agent_certificates
				 WHERE serial_number = $1 AND revoked = true
			)`, serial).Scan(&revoked)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if revoked {
			jsonError(w, "presented certificate has been revoked", http.StatusUnauthorized)
			return
		}
	} else {
		var alreadyValid bool
		err := tx.QueryRow(ctx, `
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
	}

	issued, err := h.pki.IssueClientCertificate(req.AgentID, []byte(req.CSRPEM))
	if err != nil {
		jsonError(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at)
		VALUES ($1, $2, NOW(), $3)`,
		issued.SerialNumber, req.AgentID, issued.ExpiresAt,
	); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respond(w, enrollCSRResponse{
		CertPEM:   string(issued.CertPEM),
		CAPEM:     string(h.pki.RootCertPEM()),
		ExpiresAt: issued.ExpiresAt.Format(time.RFC3339),
	})
}
