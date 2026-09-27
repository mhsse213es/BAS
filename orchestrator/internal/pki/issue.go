// orchestrator/internal/pki/issue.go
package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// clientCertValidity is the agent client certificate lifetime (spec
// Section 2 default). Renewed at ~75% elapsed or on the next binary
// upgrade's re-enroll, whichever comes first -- see Task 12.
const clientCertValidity = 365 * 24 * time.Hour

// IssuedCert is a newly signed agent client certificate plus the metadata
// the caller (Task 5's enrollment handler) persists in agent_certificates.
type IssuedCert struct {
	CertPEM      []byte
	SerialNumber string
	ExpiresAt    time.Time
}

// IssueClientCertificate parses csrPEM, verifies its self-signature, and
// signs a new mTLS client certificate for agentID using the deployment CA.
//
// agentID -- already validated by the caller against the agents table and
// enrollment policy -- is what gets stamped into the signed certificate's
// Subject.CommonName and DNSNames SAN. The CSR's own requested Subject is
// read only to prove possession of the private key (CheckSignature) and is
// otherwise ignored: per the spec, the orchestrator is authoritative for
// agent identity, not the agent's own assertion.
func (c *CA) IssueClientCertificate(agentID string, csrPEM []byte) (*IssuedCert, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("decode CSR PEM: expected a CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid (does not prove possession of the private key): %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	notBefore := time.Now().Add(-5 * time.Minute) // small clock-skew allowance
	notAfter := notBefore.Add(clientCertValidity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"Audspect"}},
		DNSNames:     []string{agentID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign client certificate: %w", err)
	}
	return &IssuedCert{
		CertPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		SerialNumber: serial.Text(16),
		ExpiresAt:    notAfter,
	}, nil
}
