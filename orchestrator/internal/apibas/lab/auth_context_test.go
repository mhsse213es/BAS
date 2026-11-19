package lab

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authTestServer is a lab server with two customers' tokens and the lab CA as the client-certificate trust anchor.
func authTestServer(t *testing.T, mode Mode) (*Server, *PKI) {
	t.Helper()
	pki, err := NewPKI()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		cfg: Config{
			Mode:      mode,
			Tokens:    map[string]string{"tok-a": "customer-a", "tok-b": "customer-b"},
			ClientCAs: pki.CAPool,
		},
		revoked: map[string]bool{},
	}, pki
}

// unsignedToken builds an alg-none token naming a subject, the shape the vulnerable verifier accepts.
func unsignedToken(sub string) string {
	enc := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]string{"alg": "none"})
	pl, _ := json.Marshal(map[string]string{"sub": sub})
	return enc(hdr) + "." + enc(pl) + "."
}

// withCert attaches a client certificate to the request as the TLS layer would, parsed so the chain check can read it.
func withCert(t *testing.T, r *http.Request, c tls.Certificate) *http.Request {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	return r
}

func TestResolveAuthCases(t *testing.T) {
	type want struct {
		identity, basis, claimed, verified string
	}
	cases := []struct {
		name string
		mode Mode
		req  func(t *testing.T, pki *PKI) *http.Request
		want want
	}{
		{"signed token", ModeFixed, func(t *testing.T, _ *PKI) *http.Request {
			r := httptest.NewRequest("GET", "/x", nil)
			r.Header.Set("Authorization", "Bearer tok-a")
			return r
		}, want{"customer-a", BasisSignedToken, "", "customer-a"}},
		{"unsigned subject, vulnerable", ModeVulnerable, func(t *testing.T, _ *PKI) *http.Request {
			r := httptest.NewRequest("GET", "/x", nil)
			r.Header.Set("Authorization", "Bearer "+unsignedToken("customer-b"))
			return r
		}, want{"customer-b", BasisUnsignedTokenClaim, "customer-b", ""}},
		{"unsigned subject, fixed: refused, no identity", ModeFixed, func(t *testing.T, _ *PKI) *http.Request {
			r := httptest.NewRequest("GET", "/x", nil)
			r.Header.Set("Authorization", "Bearer "+unsignedToken("customer-b"))
			return r
		}, want{"unknown", "", "", ""}},
		{"header claim over a valid token, vulnerable", ModeVulnerable, func(t *testing.T, _ *PKI) *http.Request {
			r := httptest.NewRequest("GET", "/x", nil)
			r.Header.Set("Authorization", "Bearer tok-a")
			r.Header.Set("X-Customer-Id", "customer-b")
			return r
		}, want{"customer-b", BasisHeaderClaim, "customer-b", "customer-a"}},
		{"header ignored, fixed: the token's identity", ModeFixed, func(t *testing.T, _ *PKI) *http.Request {
			r := httptest.NewRequest("GET", "/x", nil)
			r.Header.Set("Authorization", "Bearer tok-a")
			r.Header.Set("X-Customer-Id", "customer-b")
			return r
		}, want{"customer-a", BasisSignedToken, "", "customer-a"}},
		{"revoked or unknown token: no identity", ModeFixed, func(t *testing.T, _ *PKI) *http.Request {
			r := httptest.NewRequest("GET", "/x", nil)
			r.Header.Set("Authorization", "Bearer tok-unknown")
			return r
		}, want{"unknown", "", "", ""}},
		{"no credential at all", ModeFixed, func(t *testing.T, _ *PKI) *http.Request {
			return httptest.NewRequest("GET", "/x", nil)
		}, want{"anonymous", "", "", ""}},
		{"certificate chains to the lab CA", ModeFixed, func(t *testing.T, pki *PKI) *http.Request {
			c, err := pki.IssueClientCert("customer-b")
			if err != nil {
				t.Fatal(err)
			}
			return withCert(t, httptest.NewRequest("GET", "/x", nil), c)
		}, want{"customer-b", BasisChainVerifiedCert, "", "customer-b"}},
		{"self-signed certificate: a claim, not proof", ModeFixed, func(t *testing.T, _ *PKI) *http.Request {
			c, err := SelfSignedClientCert("customer-b")
			if err != nil {
				t.Fatal(err)
			}
			return withCert(t, httptest.NewRequest("GET", "/x", nil), c)
		}, want{"customer-b", BasisUnverifiedCertClaim, "customer-b", ""}},
		{"malformed header with a verified certificate: the certificate is the proof", ModeFixed, func(t *testing.T, pki *PKI) *http.Request {
			c, err := pki.IssueClientCert("customer-b")
			if err != nil {
				t.Fatal(err)
			}
			r := withCert(t, httptest.NewRequest("GET", "/x", nil), c)
			r.Header.Set("Authorization", "Basic abc")
			return r
		}, want{"unknown", "", "", "customer-b"}},
		{"unknown bearer with a verified certificate: the bad credential is not replaced by the certificate", ModeFixed, func(t *testing.T, pki *PKI) *http.Request {
			c, err := pki.IssueClientCert("customer-b")
			if err != nil {
				t.Fatal(err)
			}
			r := withCert(t, httptest.NewRequest("GET", "/x", nil), c)
			r.Header.Set("Authorization", "Bearer tok-unknown")
			return r
		}, want{"unknown", "", "", ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, pki := authTestServer(t, c.mode)
			r := c.req(t, pki)
			got := s.resolveAuth(r)
			if got.Identity != c.want.identity || got.Basis != c.want.basis || got.Claimed != c.want.claimed {
				t.Errorf("resolveAuth = %+v, want identity %q basis %q claimed %q", got, c.want.identity, c.want.basis, c.want.claimed)
			}
			if v := s.verifiedIdentity(r); v != c.want.verified {
				t.Errorf("verifiedIdentity = %q, want %q", v, c.want.verified)
			}
		})
	}
}

// An event with no credential carries no basis or claim, so existing event consumers see the same keys as before.
func TestAccessEventOmitsEmptyIdentityFields(t *testing.T) {
	b, err := json.Marshal(accessEvent{Seq: 1, Action: "GET /x", Outcome: "success", Identity: "anonymous", Status: 200})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "identity_basis") || strings.Contains(string(b), "claimed_identity") {
		t.Errorf("empty identity fields serialised: %s", b)
	}
}
