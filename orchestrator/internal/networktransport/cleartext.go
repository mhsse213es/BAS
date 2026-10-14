// Package networktransport adds two transport-security checks --
// cleartext-protocol detection and TLS certificate validation -- as a
// new, independently-triggerable check family. See
// docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md.
package networktransport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

// CleartextProbe tests whether a declared cleartext endpoint (e.g.
// host:80) enforces no plaintext access at all -- see the decision
// table in the design spec's Section 5.3 for every classification rule
// this type implements.
type CleartextProbe interface {
	Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string)
}

// dialFunc matches (*net.Dialer).DialContext's signature -- a seam so
// tests can inject a synthetic dial outcome without sending real traffic.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// maxBannerReadBytes bounds how much of an unprompted banner is read --
// real protocol greetings are a few dozen bytes; this is generous
// without being unbounded.
const maxBannerReadBytes = 512

// TCPCleartextProbe is the only real implementation. It never sends
// anything after connecting -- only a bare connect and a passive,
// bounded read of whatever the service offers unprompted.
type TCPCleartextProbe struct {
	dial dialFunc // nil in production use; set only by tests
}

func (p TCPCleartextProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		if isConnRefused(err) {
			return networksecurity.Secure, "connection actively refused -- nothing is listening at this cleartext endpoint"
		}
		return networksecurity.Unknown, fmt.Sprintf("connection attempt failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxBannerReadBytes)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return networksecurity.Unknown, "connection succeeded but no unprompted banner was offered -- inconclusive"
	}
	if protocol, ok := identifyCleartextBanner(buf[:n]); ok {
		return networksecurity.Insecure, fmt.Sprintf("unprompted banner positively identifies %s, a cleartext protocol", protocol)
	}
	return networksecurity.Unknown, "connection succeeded with an unrecognized or ambiguous response -- not proof of cleartext access"
}

// identifyCleartextBanner recognizes the handful of unmistakable
// plaintext protocol greetings a service might offer unprompted. Any
// response not matching one of these is left Unknown, never guessed at.
func identifyCleartextBanner(b []byte) (protocol string, matched bool) {
	s := string(b)
	switch {
	case strings.HasPrefix(s, "HTTP/"):
		return "HTTP", true
	case strings.HasPrefix(s, "220 ") || strings.HasPrefix(s, "220-"):
		return "FTP/SMTP (220 greeting)", true
	case len(b) > 0 && b[0] == 0xFF: // Telnet IAC negotiation byte
		return "Telnet", true
	default:
		return "", false
	}
}
