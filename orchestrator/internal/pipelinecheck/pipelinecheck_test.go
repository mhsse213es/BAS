package pipelinecheck

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/siem"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC) }

type fakeProber map[string]error

func (f fakeProber) Probe(_ context.Context, t Target) error { return f[t.ID] }

func siemTarget(id, provider string) Target {
	return Target{Kind: KindSIEM, ID: id, Provider: provider}
}

// No connectors configured is ERROR. An empty pipeline must never pass.
func TestOutcome_NoTargetsIsError(t *testing.T) {
	v, reasons := Outcome(Run(context.Background(), fakeProber{}, nil, fixedNow))
	if v != killchain.VerdictError || len(reasons) == 0 {
		t.Fatalf("verdict=%s reasons=%v, want ERROR with a reason", v, reasons)
	}
}

// A reachable connector is INCONCLUSIVE, never a pass, and the reasons list every stage
// connectivity does not show.
func TestOutcome_ConnectedIsInconclusiveNotPass(t *testing.T) {
	res := Run(context.Background(), fakeProber{"s1": nil}, []Target{siemTarget("s1", "qradar")}, fixedNow)
	v, reasons := Outcome(res)
	if v != killchain.VerdictInconclusive {
		t.Fatalf("verdict=%s, want INCONCLUSIVE", v)
	}
	joined := strings.Join(reasons, " | ")
	for _, want := range []string{"not proof of event ingestion", "not verified: event ingestion", "not verified: case creation", "not verified: analyst acknowledgement", "not verified: escalation", "not verified: permissions"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("reasons missing %q: %s", want, joined)
		}
	}
	if v == killchain.VerdictAllowed || v == killchain.VerdictDetected || v == killchain.VerdictBlocked {
		t.Fatalf("connectivity must never produce a detection or prevention verdict: %s", v)
	}
}

// A configured connector whose test fails is ERROR, and the failure is named.
func TestOutcome_FailedConnectorIsError(t *testing.T) {
	res := Run(context.Background(), fakeProber{"s1": errors.New("401 unauthorized")}, []Target{siemTarget("s1", "qradar")}, fixedNow)
	v, reasons := Outcome(res)
	if v != killchain.VerdictError || !strings.Contains(strings.Join(reasons, " "), "401 unauthorized") {
		t.Fatalf("verdict=%s reasons=%v, want ERROR naming the failure", v, reasons)
	}
}

// A provider with no connectivity test is ERROR as untested, not as a pass.
func TestOutcome_NotSupportedIsError(t *testing.T) {
	res := Run(context.Background(), fakeProber{"s1": ErrNotSupported}, []Target{siemTarget("s1", "splunk")}, fixedNow)
	v, reasons := Outcome(res)
	if v != killchain.VerdictError || !strings.Contains(strings.Join(reasons, " "), "not tested") {
		t.Fatalf("verdict=%s reasons=%v, want ERROR as not tested", v, reasons)
	}
}

// One failing target among healthy ones still makes the stage ERROR. Every failure is
// reported, and a healthy target cannot mask a failed one.
func TestOutcome_OneFailureMasksNothing(t *testing.T) {
	targets := []Target{siemTarget("ok", "qradar"), {Kind: KindTicketing, ID: "tk", Provider: "jira"}}
	res := Run(context.Background(), fakeProber{"ok": nil, "tk": errors.New("timeout")}, targets, fixedNow)
	v, reasons := Outcome(res)
	if v != killchain.VerdictError {
		t.Fatalf("verdict=%s, want ERROR", v)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "ticketing tk") {
		t.Fatalf("reasons=%v, want only the ticketing failure named", reasons)
	}
}

// Each result carries the time the probe ran.
func TestRun_RecordsCheckTime(t *testing.T) {
	res := Run(context.Background(), fakeProber{"s1": nil}, []Target{siemTarget("s1", "qradar")}, fixedNow)
	if !res[0].CheckedAt.Equal(fixedNow()) {
		t.Fatalf("checkedAt=%v", res[0].CheckedAt)
	}
}

// The SIEM adapter maps a provider with no connectivity test to ErrNotSupported. Only the
// unsupported branch is exercised here, so no network call is made.
func TestConnectorProber_UnsupportedSIEMProviderMapsToNotSupported(t *testing.T) {
	p := ConnectorProber{LoadSIEM: func(context.Context, string) (siem.Config, error) {
		return siem.Config{Provider: "splunk"}, nil
	}}
	err := p.Probe(context.Background(), siemTarget("s1", "splunk"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("err=%v, want ErrNotSupported", err)
	}
}

// A ticketing target goes through the connector's own test.
type fakeTicketing struct{ err error }

func (f fakeTicketing) TestConnector(context.Context, string) error { return f.err }

func TestConnectorProber_TicketingUsesConnectorTest(t *testing.T) {
	p := ConnectorProber{Ticketing: fakeTicketing{err: errors.New("bad token")}}
	if err := p.Probe(context.Background(), Target{Kind: KindTicketing, ID: "tk"}); err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("err=%v, want the ticketing failure passed through", err)
	}
}
