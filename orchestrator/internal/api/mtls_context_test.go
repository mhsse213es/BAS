package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithMTLSIdentity_AttachesCommonNameFromPeerCert(t *testing.T) {
	var gotID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = AuthenticatedAgentID(r)
	})
	wrapped := WithMTLSIdentity(inner)

	// Build a request whose TLS state carries a peer certificate with a
	// known CommonName, mirroring what net/http populates for a real mTLS
	// connection after a successful client-cert handshake.
	req := httptest.NewRequest(http.MethodGet, "/ws/agent", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "abc123deadbeef01"}}},
	}
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if gotID != "abc123deadbeef01" {
		t.Errorf("AuthenticatedAgentID = %q, want abc123deadbeef01", gotID)
	}
}

func TestWithMTLSIdentity_NoClientCertLeavesEmpty(t *testing.T) {
	var gotID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = AuthenticatedAgentID(r)
	})
	wrapped := WithMTLSIdentity(inner)

	req := httptest.NewRequest(http.MethodGet, "/ws/agent", nil) // req.TLS is nil (plaintext/legacy listener)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if gotID != "" {
		t.Errorf("AuthenticatedAgentID = %q, want empty for a non-mTLS request", gotID)
	}
}

func TestWSAgentAuthorized_MTLSIdentityMismatchRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=claimed-other-agent", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "real-authenticated-agent"}}},
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAuthenticatedAgentID, "real-authenticated-agent"))

	ok, code, _ := wsAgentAuthorized(req, "")
	if ok {
		t.Error("expected rejection when ?agentId= does not match the authenticated certificate's identity")
	}
	if code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", code)
	}
}

func TestWSAgentAuthorized_MTLSIdentityMatchAccepted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=real-authenticated-agent", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAuthenticatedAgentID, "real-authenticated-agent"))

	ok, _, _ := wsAgentAuthorized(req, "")
	if !ok {
		t.Error("expected acceptance when ?agentId= matches the authenticated certificate's identity")
	}
}

func TestWSAgentAuthorized_LegacyFallbackUnchanged(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=x&agentSecret=correct-secret", nil)
	// No context value set -- simulates the plaintext/legacy listener, where
	// WithMTLSIdentity was never applied.
	if ok, _, _ := wsAgentAuthorized(req, "correct-secret"); !ok {
		t.Error("expected acceptance with the correct legacy agentSecret")
	}
	if ok, code, _ := wsAgentAuthorized(req, "different-secret"); ok || code != http.StatusUnauthorized {
		t.Errorf("expected rejection with a wrong legacy agentSecret, got ok=%v code=%d", ok, code)
	}
}
