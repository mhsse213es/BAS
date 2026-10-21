package lab

// TLS listener behaviour and the two TLS-dependent scenarios (AUTHN-007 client certificates, GWAY-012 upstream
// certificates). Both builds complete the TLS handshake. The fixed build then refuses at the application layer, with
// the status the scenario declares. A handshake that fails is a transport error and never counts as a control result.

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"time"
)

// b4ProbeMarker is the value the TLS probe endpoint returns. It is the forbidden value for GWAY-012: relaying it from an
// untrusted upstream is the exposure.
const b4ProbeMarker = "BAS-UPSTREAM-PROBE"

// TLSConfig returns the server TLS configuration. It requests a client certificate but does not verify it during the
// handshake, in both builds. Verification is the application's job: the vulnerable build trusts the certificate's
// subject and the fixed build verifies the chain to the lab CA. TLS 1.2 is the minimum in both builds.
func (s *Server) TLSConfig(server tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{server},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
	}
}

func (s *Server) registerBatch4(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tls-probe", s.tlsProbe)
	mux.HandleFunc("POST /api/gateway/upstream-fetch", s.upstreamFetch)
	mux.HandleFunc("GET /api/mtls/orders/{id}", s.mtlsOrder)
}

func batch4Flaws() []Flaw {
	return []Flaw{
		{ID: "LAB-AUTHN-MTLS-001", ScenarioID: "API-BAS-AUTHN-007", Description: "GET /api/mtls/orders/{id} takes the caller's identity from a client certificate's subject without verifying that the certificate chains to the lab CA.", Oracle: "another tenant's protected values are returned to a caller presenting a self-signed certificate with that tenant's subject"},
		{ID: "LAB-GWAY-UPSTREAM-001", ScenarioID: "API-BAS-GWAY-012", Description: "POST /api/gateway/upstream-fetch fetches an upstream over TLS without verifying its certificate, and relays the content.", Oracle: "content from an upstream with an untrusted certificate is relayed to the caller"},
	}
}

// tlsProbe is the upstream content for GWAY-012. It needs no credential.
func (s *Server) tlsProbe(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"probe": b4ProbeMarker})
}

// upstreamFetch fetches a URL over TLS and relays the body. The fixed build verifies the upstream certificate against
// the lab's trusted roots. An upstream that fails verification is refused with 422 (GWAY-012).
func (s *Server) upstreamFetch(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &req); err != nil || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}
	tlsCfg := &tls.Config{RootCAs: s.cfg.UpstreamRoots}
	if s.vulnerable() {
		tlsCfg.InsecureSkipVerify = true // the defect under test: the upstream certificate is not checked
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := client.Get(req.URL)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "upstream could not be verified"})
		return
	}
	defer resp.Body.Close()
	if resp.TLS != nil {
		u, _ := url.Parse(req.URL)
		noteUpstream(r, req.URL, upstreamVerified(resp.TLS, s.cfg.UpstreamRoots, u.Hostname()))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	writeJSON(w, http.StatusOK, map[string]any{"upstream_status": resp.StatusCode, "body": string(body)})
}

// mtlsOrder returns an order to the holder of a client certificate. The fixed build requires the certificate to chain
// to the lab CA. Both builds complete the handshake first (AUTHN-007).
func (s *Server) mtlsOrder(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "client certificate required"})
		return
	}
	leaf := r.TLS.PeerCertificates[0]
	if !s.vulnerable() {
		if s.cfg.ClientCAs == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no client CA configured"})
			return
		}
		intermediates := x509.NewCertPool()
		for _, c := range r.TLS.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         s.cfg.ClientCAs,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "client certificate not trusted"})
			return
		}
	}
	identity := leaf.Subject.CommonName
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != identity {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": o.ID, "fields": mergeFields(o.Public, o.Protected)})
}

// certClaim returns the common name of the client certificate a request presented, which the vulnerable build trusts
// as the caller's identity. The fixed build refuses an untrusted certificate before any identity is used.
func (s *Server) certClaim(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName, true
}

// certIdentity returns the common name of a client certificate that chains to the lab CA. It is the identity the
// certificate proves. A certificate that does not chain proves nothing (AUTHN-007).
func (s *Server) certIdentity(r *http.Request) (string, bool) {
	cn, ok := s.certClaim(r)
	if !ok || s.cfg.ClientCAs == nil {
		return "", false
	}
	inter := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots: s.cfg.ClientCAs, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", false
	}
	return cn, true
}
