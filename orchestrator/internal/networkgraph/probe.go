package networkgraph

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

// TCPReachabilityProbe performs one bounded TCP reachability check against
// target, classifying the outcome as a cloudgraph.PathState. No data is
// sent or read beyond the TCP handshake itself -- this is a pure
// reachability check, never a service/banner probe.
type TCPReachabilityProbe interface {
	Probe(ctx context.Context, target Target, timeout time.Duration) (cloudgraph.PathState, error)
}

// dialFunc matches (*net.Dialer).DialContext's signature -- a seam so
// tests can inject a synthetic dial outcome (e.g. a generic timeout-style
// error) without ever sending traffic off this host. Production code
// always uses the real dialer.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialerProbe is the only real implementation:
//   - connection succeeds               -> Observed (closed immediately, nothing sent/read)
//   - connection actively refused       -> Blocked
//   - timeout, or any other dial error  -> Unknown (never Blocked -- a timeout proves nothing about why)
type DialerProbe struct {
	dial dialFunc // nil in production use; set only by tests
}

func (p DialerProbe) Probe(ctx context.Context, target Target, timeout time.Duration) (cloudgraph.PathState, error) {
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	conn, err := dial(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		return cloudgraph.Observed, nil
	}
	if isConnRefused(err) {
		return cloudgraph.Blocked, err
	}
	return cloudgraph.Unknown, err
}
