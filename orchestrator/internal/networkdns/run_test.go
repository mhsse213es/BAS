package networkdns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

type stubOpenResolverProbe struct {
	state cloudgraph.PathState
	err   error
}

func (s stubOpenResolverProbe) Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) {
	return s.state, s.err
}

func TestRunChecks_OpenResolverCheck_ProducesObservation(t *testing.T) {
	checks := []DNSCheckRequest{{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.5", Port: 53}, QueryDomain: "example.test."}}
	result, err := RunChecks(context.Background(), stubOpenResolverProbe{state: cloudgraph.Blocked}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 1 || result.Results[0].CheckType != CheckOpenResolver {
		t.Fatalf("got %+v, want one open-resolver result", result.Results)
	}
	if result.Results[0].Observation == nil || result.Results[0].Observation.State != cloudgraph.Blocked {
		t.Fatalf("Observation = %+v, want State=Blocked", result.Results[0].Observation)
	}
	if result.Results[0].DNSSEC != nil {
		t.Fatal("DNSSEC must be nil for an open-resolver check result")
	}
}

func TestRunChecks_EmptyChecksRejected(t *testing.T) {
	_, err := RunChecks(context.Background(), stubOpenResolverProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, nil)
	if err == nil {
		t.Fatal("want an error for zero checks")
	}
}

func TestRunChecks_TooManyChecksRejected(t *testing.T) {
	checks := make([]DNSCheckRequest, MaxChecksPerRun+1)
	for i := range checks {
		checks[i] = DNSCheckRequest{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.5", Port: 53}, QueryDomain: "example.test."}
	}
	_, err := RunChecks(context.Background(), stubOpenResolverProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err == nil {
		t.Fatal("want an error for exceeding MaxChecksPerRun")
	}
}

func TestRunChecks_OneFailingCheckDoesNotBlockOthers(t *testing.T) {
	checks := []DNSCheckRequest{
		{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.5", Port: 53}, QueryDomain: "fails.test."},
		{CheckType: CheckOpenResolver, Target: networkgraph.Target{Host: "10.0.1.6", Port: 53}, QueryDomain: "succeeds.test."},
	}
	failingProbe := failingOnDomainProbe{failDomain: "fails.test."}
	result, err := RunChecks(context.Background(), failingProbe, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2 -- one check's failure must not drop the other's result", len(result.Results))
	}
}

// TestRunChecks_DNSSECCheck_ProducesDNSSECResult pins Review Focus item
// 5 (the DNSCheckResult tagged union) for the DNSSEC side: a
// CheckDNSSEC request must produce a populated DNSSEC field and a nil
// Observation, end-to-end through RunChecks's real ValidateDNSSEC call
// -- not merely through validateChain's own lower-level unit tests,
// which never exercise this call path at all.
func TestRunChecks_DNSSECCheck_ProducesDNSSECResult(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(resp)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })

	original := defaultDNSResolverAddr
	defaultDNSResolverAddr = pc.LocalAddr().String()
	t.Cleanup(func() { defaultDNSResolverAddr = original })

	checks := []DNSCheckRequest{{CheckType: CheckDNSSEC, QueryDomain: "example-test."}}
	result, err := RunChecks(context.Background(), stubOpenResolverProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 1 || result.Results[0].CheckType != CheckDNSSEC {
		t.Fatalf("got %+v, want one dnssec result", result.Results)
	}
	if result.Results[0].DNSSEC == nil {
		t.Fatal("DNSSEC must be populated for a dnssec check result")
	}
	if result.Results[0].Observation != nil {
		t.Fatal("Observation must be nil for a dnssec check result")
	}
}

type failingOnDomainProbe struct{ failDomain string }

func (f failingOnDomainProbe) Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) {
	if queryDomain == f.failDomain {
		return cloudgraph.Unknown, errors.New("simulated probe failure")
	}
	return cloudgraph.Observed, nil
}
