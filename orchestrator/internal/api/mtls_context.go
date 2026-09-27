package api

import (
	"context"
	"crypto/subtle"
	"net/http"
)

type ctxKey int

const (
	ctxKeyAuthenticatedAgentID ctxKey = iota
	ctxKeyLegacyListener              // set by WithLegacyListenerTag (observability.go)
)

// WithMTLSIdentity wraps next so that any request arriving with a verified
// client certificate (i.e. requests on the mTLS-required 9443 listener —
// see Task 7's main.go wiring) has the certificate's CommonName attached to
// its context. That CommonName is the server-authoritative AgentID stamped
// in by pki.IssueClientCertificate (Task 3) at enrollment time.
//
// A request with no client certificate (the enrollment or legacy listeners,
// where req.TLS is nil or carries no PeerCertificates) passes through
// unchanged; AuthenticatedAgentID returns "" for it.
func WithMTLSIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn := r.TLS.PeerCertificates[0].Subject.CommonName
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyAuthenticatedAgentID, cn))
		}
		next.ServeHTTP(w, r)
	})
}

// AuthenticatedAgentID returns the AgentID established by a verified mTLS
// client certificate on this connection, or "" if the request arrived
// without one.
func AuthenticatedAgentID(r *http.Request) string {
	v, _ := r.Context().Value(ctxKeyAuthenticatedAgentID).(string)
	return v
}

// wsAgentAuthorized decides whether a /ws/agent request may proceed, before
// any WebSocket upgrade is attempted. An mTLS-authenticated connection
// (mtlsID != "") must have its claimed agentId query param match the
// certificate's identity exactly -- a cert issued for one agent must never
// be usable to claim another's identity. A connection with no mTLS
// identity (enrollment/legacy listeners) falls back to the pre-existing
// agentSecret query param/X-Agent-Token header check, unchanged from
// today. Returns (true, 0, "") to proceed, or (false, statusCode, message)
// to reject.
func wsAgentAuthorized(req *http.Request, agentSecret string) (ok bool, statusCode int, msg string) {
	claimedID := req.URL.Query().Get("agentId")
	if mtlsID := AuthenticatedAgentID(req); mtlsID != "" {
		if claimedID != mtlsID {
			return false, http.StatusUnauthorized, "agentId does not match authenticated certificate"
		}
		return true, 0, ""
	}
	if agentSecret != "" {
		provided := req.URL.Query().Get("agentSecret")
		if provided == "" {
			provided = req.Header.Get("X-Agent-Token")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(agentSecret)) != 1 {
			return false, http.StatusUnauthorized, "unauthorized"
		}
	}
	return true, 0, ""
}
