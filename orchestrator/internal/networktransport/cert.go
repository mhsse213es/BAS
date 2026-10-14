package networktransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

// CertProbe inspects a target's presented TLS certificate without
// failing the handshake on an invalid cert (InsecureSkipVerify), then
// verifies expiry, hostname match, and chain trust itself via
// x509.Certificate.Verify -- which checks all three atomically and
// produces a specific, already-descriptive error for any failure.
type CertProbe interface {
	Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string)
}

// TLSCertProbe is the only real implementation. roots is nil in
// production (system roots); tests inject their own CA pool, since
// Go's x509.Verify always rejects a cert chain the pool wasn't built
// to trust -- there is no way to make a self-signed test cert
// trusted by the real system root store.
//
// This probe never attempts to negotiate below TLS 1.2: Go's TLS
// client already refuses to do so by default (since Go 1.18), so a
// successful handshake using this probe's own dialer is already
// implicit proof the negotiated version meets that floor. Lowering
// the client's own MinVersion to actively test what a server would
// negotiate down to is the deferred downgrade-testing capability
// (design spec Section 8) and must not be added here.
type TLSCertProbe struct {
	roots *x509.CertPool
}

func (p TLSCertProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return networksecurity.Unknown, fmt.Sprintf("TLS handshake failed: %v", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return networksecurity.Unknown, "dialed connection was not a TLS connection"
	}
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return networksecurity.Unknown, "handshake succeeded but no peer certificate was presented"
	}

	if _, err := peerCerts[0].Verify(x509.VerifyOptions{DNSName: target.Host, Roots: p.roots}); err != nil {
		return networksecurity.Insecure, fmt.Sprintf("certificate is invalid: %v", err)
	}
	return networksecurity.Secure, ""
}
