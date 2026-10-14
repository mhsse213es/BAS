package networktransport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

type stubCleartextProbe struct {
	state  networksecurity.SecurityState
	reason string
}

func (s stubCleartextProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	return s.state, s.reason
}

type stubCertProbe struct {
	state  networksecurity.SecurityState
	reason string
}

func (s stubCertProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	return s.state, s.reason
}

func TestRunChecks_BothCheckTypes_ProduceResults(t *testing.T) {
	checks := []TransportCheckRequest{
		{CheckType: CheckCleartext, Target: networkgraph.Target{Host: "127.0.0.1", Port: 80}},
		{CheckType: CheckCert, Target: networkgraph.Target{Host: "127.0.0.1", Port: 443}},
	}
	result, err := RunChecks(context.Background(),
		stubCleartextProbe{state: networksecurity.Secure},
		stubCertProbe{state: networksecurity.Insecure, reason: "expired"},
		networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(result.Results))
	}
	var sawCleartext, sawCert bool
	for _, r := range result.Results {
		if r.Target.Port == 80 {
			sawCleartext = true
			if r.State != networksecurity.Secure {
				t.Fatalf("cleartext result State = %q, want Secure", r.State)
			}
		}
		if r.Target.Port == 443 {
			sawCert = true
			if r.State != networksecurity.Insecure || r.Reason != "expired" {
				t.Fatalf("cert result = %+v, want Insecure/expired", r)
			}
		}
	}
	if !sawCleartext || !sawCert {
		t.Fatalf("missing a result: cleartext=%v cert=%v", sawCleartext, sawCert)
	}
}

// TestRunChecks_UnrecognizedCheckType_Unknown pins a real bug:
// runOneCheck's switch had a bare `default` branch that silently
// routed anything not CheckCert to the cleartext probe -- a typo'd or
// stale CheckType would run the wrong probe against the target and
// still get persisted under its own (incorrect) check_type, with no
// way to tell from the result that anything was wrong.
func TestRunChecks_UnrecognizedCheckType_Unknown(t *testing.T) {
	checks := []TransportCheckRequest{
		{CheckType: CheckType("bogus"), Target: networkgraph.Target{Host: "127.0.0.1", Port: 80}},
	}
	result, err := RunChecks(context.Background(),
		stubCleartextProbe{state: networksecurity.Secure}, // must never be reached for an unrecognized type
		stubCertProbe{},
		networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(result.Results))
	}
	if result.Results[0].State != networksecurity.Unknown {
		t.Fatalf("State = %q, want unknown -- an unrecognized check type must never be silently routed to a real probe", result.Results[0].State)
	}
}

func TestRunChecks_EmptyChecksRejected(t *testing.T) {
	_, err := RunChecks(context.Background(), stubCleartextProbe{}, stubCertProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, nil)
	if err == nil {
		t.Fatal("want an error for zero checks")
	}
}

func TestRunChecks_TooManyChecksRejected(t *testing.T) {
	checks := make([]TransportCheckRequest, MaxChecksPerRun+1)
	for i := range checks {
		checks[i] = TransportCheckRequest{CheckType: CheckCleartext, Target: networkgraph.Target{Host: "127.0.0.1", Port: 80}}
	}
	_, err := RunChecks(context.Background(), stubCleartextProbe{}, stubCertProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err == nil {
		t.Fatal("want an error for exceeding MaxChecksPerRun")
	}
}

func TestRunChecks_OneFailingCheckDoesNotBlockOthers(t *testing.T) {
	checks := []TransportCheckRequest{
		{CheckType: CheckCleartext, Target: networkgraph.Target{Host: "10.0.1.6", Port: 80}},
		{CheckType: CheckCert, Target: networkgraph.Target{Host: "10.0.1.7", Port: 443}},
	}
	result, err := RunChecks(context.Background(),
		failingCleartextProbe{},
		stubCertProbe{state: networksecurity.Secure},
		networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2 -- one check's failure must not drop the other's result", len(result.Results))
	}
}

type failingCleartextProbe struct{}

func (failingCleartextProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	return networksecurity.Unknown, errSimulatedProbeFailure.Error()
}

var errSimulatedProbeFailure = errors.New("simulated probe failure")
