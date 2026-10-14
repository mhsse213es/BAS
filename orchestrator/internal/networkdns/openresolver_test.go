package networkdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/miekg/dns"
)

func TestDNSOpenResolverProbe_AnswerComesBack_Observed(t *testing.T) {
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeSuccess
		rr, _ := dns.NewRR("example.test. 300 IN A 192.0.2.1")
		resp.Answer = append(resp.Answer, rr)
		return resp, nil
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Observed {
		t.Fatalf("state = %q, want Observed -- the resolver answered a recursive query it shouldn't have", state)
	}
}

func TestDNSOpenResolverProbe_Refused_Blocked(t *testing.T) {
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeRefused
		return resp, nil
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Blocked {
		t.Fatalf("state = %q, want Blocked -- REFUSED means correctly restricted", state)
	}
}

func TestDNSOpenResolverProbe_Timeout_Unknown(t *testing.T) {
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		return nil, errors.New("i/o timeout")
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err == nil {
		t.Fatal("want a non-nil error alongside Unknown")
	}
	if state != cloudgraph.Unknown {
		t.Fatalf("state = %q, want Unknown -- a timeout proves nothing, never Blocked", state)
	}
}

func TestDNSOpenResolverProbe_ReferralComesBack_Observed(t *testing.T) {
	// A referral (no answer, but authority records pointing elsewhere)
	// still proves the resolver attempted recursion for a domain outside
	// its own authority -- the same misconfiguration as a direct answer.
	p := DNSOpenResolverProbe{exchange: func(m *dns.Msg, addr string) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeSuccess
		ns, _ := dns.NewRR("test. 300 IN NS ns1.test.")
		resp.Ns = append(resp.Ns, ns)
		return resp, nil
	}}
	state, err := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 53}, "example.test.", time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Observed {
		t.Fatalf("state = %q, want Observed", state)
	}
}
