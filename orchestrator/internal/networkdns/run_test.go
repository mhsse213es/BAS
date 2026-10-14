package networkdns

import (
	"context"
	"errors"
	"testing"
	"time"

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

type failingOnDomainProbe struct{ failDomain string }

func (f failingOnDomainProbe) Probe(ctx context.Context, target networkgraph.Target, queryDomain string, timeout time.Duration) (cloudgraph.PathState, error) {
	if queryDomain == f.failDomain {
		return cloudgraph.Unknown, errors.New("simulated probe failure")
	}
	return cloudgraph.Observed, nil
}
