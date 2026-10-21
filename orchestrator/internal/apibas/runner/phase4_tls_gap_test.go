package runner_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// TLS gaps from the Phase 3 close-out, closed where a test can show them. Expectations, written before the run:
//
//   other CA   a client certificate with the subject cust-a, signed by a CA the lab does not trust. The vulnerable build
//              trusts the subject and returns cust-a's data (FAIL). The fixed build verifies the chain and refuses it
//              at the application layer (PASS).
//   expired    the same subject, signed by the lab CA but outside its validity window. The fixed build refuses it on
//              validity (PASS). The vulnerable build ignores validity and trusts the subject (FAIL).
//   version    a client that offers only TLS 1.1 is refused by both builds at the handshake. The lab's minimum is TLS 1.2.
//
// Not closed here: certificate revocation (CRL/OCSP). The lab has no revocation source, so no revocation result is claimed.

// issueClientCert signs a client certificate for cn with the given CA and validity window.
func issueClientCert(t *testing.T, ca *lab.PKI, cn string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.CA, &key.PublicKey, ca.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestTLS_GapOtherCAAndExpiredClientCert runs AUTHN-007 with a cust-a certificate that the fixed build must refuse on
// trust (other CA) or on validity (expired), in both builds.
func TestTLS_GapOtherCAAndExpiredClientCert(t *testing.T) {
	if testing.Short() {
		t.Skip("TLS gap run skipped in -short mode")
	}
	s := tlsScenario(t, "API-BAS-AUTHN-007")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	now := time.Now()
	otherCA, err := lab.NewPKI()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		cert  func(e *tlsEnv) tls.Certificate
		fault string
	}{
		{"other-ca", func(*tlsEnv) tls.Certificate {
			return issueClientCert(t, otherCA, "cust-a", now.Add(-time.Hour), now.Add(24*time.Hour))
		}, "trust"},
		{"expired", func(e *tlsEnv) tls.Certificate {
			return issueClientCert(t, e.pki, "cust-a", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
		}, "validity"},
	}
	for _, c := range cases {
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newTLSEnv(t, mode, fx, true, true)
			e.certs["forged-cust-a"] = c.cert(e)
			o := e.run(t, s).Outcome
			if mode == lab.ModeVulnerable {
				if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
					t.Errorf("%s vulnerable: %s/%s (%s), want FAIL/exploited (subject is trusted without %s)", c.name, o.Result, o.Exploitability, o.Reason, c.fault)
				}
			} else if o.Result != grade.PASS || o.Control != grade.Enforced {
				t.Errorf("%s fixed: %s/%s (%s), want PASS/enforced (%s checked)", c.name, o.Result, o.Control, o.Reason, c.fault)
			}
			if mode == lab.ModeFixed && o.Reason == grade.ReasonTargetUnreachable {
				t.Errorf("%s fixed: refused at the transport, want the application layer to refuse", c.name)
			}
		}
	}
}

// TestTLS_GapVersionBelowTLS12Refused offers only TLS 1.1 to each build. The handshake must fail in both, so no
// application result is produced for a legacy version.
func TestTLS_GapVersionBelowTLS12Refused(t *testing.T) {
	fx := fixtureFor(t, "orders-two-tenant")
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newTLSEnv(t, mode, fx, true, false)
		conn, err := tls.Dial("tcp", strings.TrimPrefix(e.url, "https://"), &tls.Config{
			RootCAs:    e.roots,
			MaxVersion: tls.VersionTLS11,
		})
		if err == nil {
			conn.Close()
			t.Errorf("%s: a TLS 1.1 handshake completed, want it refused", modeName(mode))
		}
	}
}
