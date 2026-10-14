// Package networkdns adds two DNS-security checks -- an open-resolver
// reachability test and a DNSSEC chain validator -- as a new,
// independently-triggerable check family. It does not modify
// internal/dnssink (a passive DNS-tunnel-exfiltration receiver, zero
// overlap) or internal/networkgraph's existing types, which it reuses
// read-only. See
// docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md.
package networkdns

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

// OpenResolverProbe performs one bounded, single recursive DNS query
// against target, classifying whether the resolver answered a query it
// shouldn't have.
type OpenResolverProbe interface {
	Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error)
}

// exchangeFunc matches the shape of a single query/response round trip
// -- a seam so tests can inject a synthetic DNS response without ever
// sending real traffic. Production code always uses the real dns.Client.
type exchangeFunc func(m *dns.Msg, addr string) (*dns.Msg, error)

// DNSOpenResolverProbe is the only real implementation:
//   - any answer or referral       -> Observed (misconfigured: it recursed)
//   - REFUSED                      -> Blocked (correctly restricted)
//   - timeout, or any other error  -> Unknown (never Blocked -- a timeout proves nothing)
type DNSOpenResolverProbe struct {
	exchange exchangeFunc // nil in production use; set only by tests
}

func (p DNSOpenResolverProbe) Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(queryDomain), dns.TypeA)
	m.RecursionDesired = true

	addr := net.JoinHostPort(target.Host, portOrDefault(target.Port))

	exchange := p.exchange
	if exchange == nil {
		client := &dns.Client{Timeout: timeout}
		exchange = func(msg *dns.Msg, a string) (*dns.Msg, error) {
			resp, _, err := client.ExchangeContext(ctx, msg, a)
			return resp, err
		}
	}

	resp, err := exchange(m, addr)
	if err != nil {
		return cloudgraph.Unknown, err
	}
	if resp.Rcode == dns.RcodeRefused {
		return cloudgraph.Blocked, nil
	}
	if len(resp.Answer) > 0 || len(resp.Ns) > 0 {
		return cloudgraph.Observed, nil
	}
	return cloudgraph.Unknown, nil
}

func portOrDefault(port int) string {
	if port == 0 {
		return "53"
	}
	return strconv.Itoa(port)
}
