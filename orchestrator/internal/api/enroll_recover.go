package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/pki"
)

// Restricted recovery of an agent whose certificate has just expired (audit F-03/F-06).
//
// The normal path stays untouched: a valid certificate authenticates over mTLS and renews there, and an
// expired one is refused at the TLS handshake on the agent listener. Recovery is a separate, narrow endpoint
// on the enrolment listener (which never accepted client certificates), so no certificate validation is
// weakened anywhere. It issues one new certificate, for the SAME AgentID, and nothing else.
//
// The caller proves it is the agent by presenting its expired certificate and a signature, made with that
// certificate's private key, over a fresh timestamp and the new CSR. The 24 hours are counted on the
// server's clock from the certificate's own NotAfter. Each expired certificate can be used once.

// recoveryGrace is how long after expiry an agent may recover with its old certificate. After this, a fresh
// authorized enrolment (an operator-issued token, or the shared secret in secret mode) is required.
const recoveryGrace = 24 * time.Hour

// recoveryProofSkew is how far the proof's timestamp may differ from the server's clock.
const recoveryProofSkew = 5 * time.Minute

type recoverRequest struct {
	AgentID        string `json:"agentId"`
	CSRPEM         string `json:"csrPem"`
	ExpiredCertPEM string `json:"expiredCertPem"`
	SignedAt       string `json:"signedAt"`
	Proof          string `json:"proof"` // base64 ASN.1 ECDSA signature over recoveryProofDigest
}

func (h *Handler) timeNow() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

// recoveryProofDigest is the exact value the agent signs. It binds the proof to the agent, to a moment, and
// to the submitted CSR, so a captured request cannot be pointed at a different key. The agent computes the
// same value (pinned by a golden vector test on both sides).
func recoveryProofDigest(agentID, signedAt, csrPEM string) [32]byte {
	csrSum := sha256.Sum256([]byte(csrPEM))
	return sha256.Sum256([]byte("BAS-RECOVER-V1\n" + agentID + "\n" + signedAt + "\n" + hex.EncodeToString(csrSum[:])))
}

// POST /api/agents/recover-csr (enrolment listener only).
func (h *Handler) RecoverCSR(w http.ResponseWriter, r *http.Request) {
	if h.pki == nil {
		jsonError(w, "PKI not configured on this deployment", http.StatusServiceUnavailable)
		return
	}
	ip := clientIP(r)
	if h.enrollThrottle.blocked(ip) {
		jsonError(w, "too many failed attempts — try again later", http.StatusTooManyRequests)
		return
	}
	var req recoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" || req.CSRPEM == "" || req.ExpiredCertPEM == "" {
		jsonError(w, "invalid request — agentId, csrPem and expiredCertPem required", http.StatusBadRequest)
		return
	}
	if !agentIDPattern.MatchString(req.AgentID) {
		jsonError(w, "invalid agentId — expected 16 lowercase hex characters", http.StatusBadRequest)
		return
	}

	deny := func(status int, public, reason string, extra map[string]any) {
		h.enrollThrottle.fail(ip)
		details := map[string]any{"reason": reason}
		for k, v := range extra {
			details[k] = v
		}
		h.auditLogAs(r, "agent:"+req.AgentID, "agent.recover_denied", req.AgentID, details, "denied")
		jsonError(w, public, status)
	}
	const refused = "recovery refused — a fresh authorized enrolment is required"

	// 1. The old certificate: ours (chains to a trusted CA, ignoring its expiry), for this agent, ECDSA.
	blk, _ := pem.Decode([]byte(req.ExpiredCertPEM))
	if blk == nil {
		deny(http.StatusBadRequest, "expiredCertPem is not a certificate", "unparseable certificate", nil)
		return
	}
	old, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		deny(http.StatusBadRequest, "expiredCertPem is not a certificate", "unparseable certificate", nil)
		return
	}
	roots := x509.NewCertPool()
	trusted := []*x509.Certificate{h.pki.Certificate()}
	if h.pkiDir != "" {
		if rs, err := pki.TrustedClientRoots(h.pkiDir); err == nil {
			trusted = rs
		}
	}
	for _, c := range trusted {
		roots.AddCert(c)
	}
	// Verified as of just before it expired: expiry is the one thing recovery is allowed to look past, and it
	// is judged separately below against the server's own clock.
	if _, err := old.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: old.NotAfter.Add(-time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		deny(http.StatusForbidden, refused, "certificate does not chain to a trusted CA", nil)
		return
	}
	if old.Subject.CommonName != req.AgentID {
		deny(http.StatusForbidden, refused, "certificate belongs to a different agent", map[string]any{"certificateAgent": old.Subject.CommonName})
		return
	}
	serial := old.SerialNumber.Text(16)

	// 2. The grace window, on the server's clock.
	now := h.timeNow()
	if now.Before(old.NotAfter) {
		h.auditLogAs(r, "agent:"+req.AgentID, "agent.recover_denied", req.AgentID, map[string]any{"reason": "certificate still valid", "serial": serial}, "denied")
		jsonError(w, "the certificate is still valid — renew over mTLS instead", http.StatusConflict)
		return
	}
	if now.After(old.NotAfter.Add(recoveryGrace)) {
		deny(http.StatusForbidden, refused, "grace period over", map[string]any{"serial": serial, "expiredFor": now.Sub(old.NotAfter).Round(time.Second).String()})
		return
	}

	// 3. Proof of possession: fresh, and covering this CSR.
	signedAt, err := time.Parse(time.RFC3339, req.SignedAt)
	if err != nil || signedAt.Before(now.Add(-recoveryProofSkew)) || signedAt.After(now.Add(recoveryProofSkew)) {
		deny(http.StatusForbidden, refused, "proof timestamp missing or outside the allowed window", map[string]any{"serial": serial})
		return
	}
	pub, ok := old.PublicKey.(*ecdsa.PublicKey)
	sig, decErr := base64.StdEncoding.DecodeString(req.Proof)
	digest := recoveryProofDigest(req.AgentID, req.SignedAt, req.CSRPEM)
	if !ok || decErr != nil || len(sig) == 0 || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		deny(http.StatusForbidden, refused, "proof of possession invalid", map[string]any{"serial": serial})
		return
	}

	// 4. State checks and issuance, serialized per agent like every other issuance.
	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('agent_certificates:' || $1, 0))`, req.AgentID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var blockedAgent bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = $1 AND state IN ('revoked','disabled','uninstalling'))`, req.AgentID).Scan(&blockedAgent); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if blockedAgent {
		deny(http.StatusForbidden, refused, "agent is revoked, disabled or being removed", map[string]any{"serial": serial})
		return
	}
	// The certificate must be one this server issued, to this agent, not revoked, not already used up, and the
	// newest one the agent was given (an older one cannot be used to roll an agent back).
	var usable bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM agent_certificates c
			 WHERE c.serial_number = $1 AND c.agent_id = $2 AND c.revoked = false AND c.superseded_at IS NULL
			   AND NOT EXISTS (SELECT 1 FROM agent_certificates n WHERE n.agent_id = c.agent_id AND n.issued_at > c.issued_at))`,
		serial, req.AgentID).Scan(&usable); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !usable {
		deny(http.StatusForbidden, refused, "certificate unknown, revoked, already used or superseded", map[string]any{"serial": serial})
		return
	}

	issued, err := h.pki.IssueClientCertificate(req.AgentID, []byte(req.CSRPEM))
	if err != nil {
		jsonError(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	var signingKeyID *string
	if h.signingKey != nil {
		id := h.signingKey.KeyID()
		signingKeyID = &id
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at, command_signing_key_id)
		VALUES ($1, $2, NOW(), $3, $4)`, issued.SerialNumber, req.AgentID, issued.ExpiresAt, signingKeyID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_certificates SET superseded_at = NOW() WHERE serial_number = $1`, serial); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLogAs(r, "agent:"+req.AgentID, "agent.recover", req.AgentID,
		map[string]any{"previousSerial": serial, "serial": issued.SerialNumber, "expiredFor": now.Sub(old.NotAfter).Round(time.Second).String()}, "ok")

	resp := enrollCSRResponse{
		CertPEM:   string(issued.CertPEM),
		CAPEM:     string(h.pki.RootCertPEM()),
		ExpiresAt: issued.ExpiresAt.Format(time.RFC3339),
	}
	if h.signingKey != nil {
		resp.CommandSigningTrust = commandSigningTrust{KeyID: h.signingKey.KeyID(), CertPEM: string(h.signingKey.CertPEM())}
	}
	respond(w, resp)
}
