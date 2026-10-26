package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// RevocationCheck reports whether a presented client certificate (its serial in lower-case hex and
// the AgentID in its CommonName) must be refused. An error also refuses the connection.
type RevocationCheck func(serialHex, agentID string) (revoked bool, err error)

// NewAgentTLSConfig is the mutual-TLS configuration for the agent listener: a client certificate is
// required and must chain to the deployment CA (the standard library also enforces expiry and the
// client-auth usage), and every connection, including a resumed session, is checked against check
// so a revoked certificate stops working at once rather than at expiry. A nil check disables only
// the revocation step.
func NewAgentTLSConfig(getServerCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), ca *CA, check RevocationCheck) *tls.Config {
	return NewAgentTLSConfigWithRoots(getServerCert, []*x509.Certificate{ca.Certificate()}, check)
}

// NewAgentTLSConfigWithRoots is NewAgentTLSConfig for an explicit set of trusted CAs: during a planned CA
// rotation that is the current CA plus the previous one (see TrustedClientRoots).
func NewAgentTLSConfigWithRoots(getServerCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), roots []*x509.Certificate, check RevocationCheck) *tls.Config {
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	return &tls.Config{
		GetCertificate: getServerCert,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      pool,
		MinVersion:     tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if check == nil {
				return nil
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate presented")
			}
			leaf := cs.PeerCertificates[0]
			revoked, err := check(leaf.SerialNumber.Text(16), leaf.Subject.CommonName)
			if err != nil {
				return fmt.Errorf("revocation check failed, refusing the connection: %w", err)
			}
			if revoked {
				return errors.New("client certificate has been revoked")
			}
			return nil
		},
	}
}
