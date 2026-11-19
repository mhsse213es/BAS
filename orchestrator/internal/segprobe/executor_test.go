package segprobe

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeProvider struct {
	healthyErr map[Zone]error
	result     ProbeResult
	probeErr   error
	events     []FirewallEvent
	fwOK       bool
	fwErr      error
}

func (f *fakeProvider) Healthy(_ context.Context, z Zone) error { return f.healthyErr[z] }
func (f *fakeProvider) Lookup(z Zone) (string, error)           { return "10.0.0." + string(z[0]), nil }
func (f *fakeProvider) TargetIP(z Zone) (string, error)         { return "10.0.0." + string(z[0]), nil }
func (f *fakeProvider) Probe(_ context.Context, _ ProbeRequest) (ProbeResult, error) {
	return f.result, f.probeErr
}
func (f *fakeProvider) FirewallEvents(_ context.Context, _ TimeWindow) ([]FirewallEvent, bool, error) {
	return f.events, f.fwOK, f.fwErr
}

func TestRunScenario_DestinationDown_IsError(t *testing.T) {
	noGap(t)
	p := &fakeProvider{healthyErr: map[Zone]error{ZoneSWIFT: errors.New("down")}, fwOK: true}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != ERROR {
		t.Fatalf("got %s, want ERROR", got.Outcomes[0].Verdict)
	}
}

func TestRunScenario_BlockedWithEvidence_IsPass(t *testing.T) {
	noGap(t)
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Second)},
		events: []FirewallEvent{{Time: start, RuleID: "SEG-DENY-SWIFT", Action: "DROP", SrcIP: "10.0.0.c", DstIP: "10.0.0.s", DstPort: 8443, Proto: "tcp"}},
		fwOK:   true,
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != PASS {
		t.Fatalf("got %s (%s), want PASS", got.Outcomes[0].Verdict, got.Outcomes[0].Reason)
	}
}

func TestRunScenario_ProbeTransportError_IsError(t *testing.T) {
	noGap(t)
	p := &fakeProvider{probeErr: errors.New("exec failed"), fwOK: true}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != ERROR {
		t.Fatalf("got %s, want ERROR", got.Outcomes[0].Verdict)
	}
}

func TestRunScenario_FirewallLogErrorIsUnknownNotPass(t *testing.T) {
	noGap(t)
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Second)},
		fwErr:  errors.New("log unreadable"),
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != UNKNOWN {
		t.Fatalf("got %s, want UNKNOWN", got.Outcomes[0].Verdict)
	}
}

// A same-zone probe never crosses seg-fw, so its verdict must not depend on
// the firewall log: connected is PASS even when the log is unreadable.
func TestRunScenario_SameZoneConnected_IsPassWithoutFirewall(t *testing.T) {
	noGap(t)
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeConnected, Start: start, End: start.Add(time.Millisecond)},
		fwErr:  errors.New("log unreadable"),
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneSWIFT, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectAllow}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != PASS {
		t.Fatalf("got %s (%s), want PASS", got.Outcomes[0].Verdict, got.Outcomes[0].Reason)
	}
}

func TestRunScenario_SameZoneRefused_IsError(t *testing.T) {
	noGap(t)
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeRefused, Start: start, End: start.Add(time.Millisecond)},
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneATM, Dst: ZoneATM, DstPort: 9000, Proto: "tcp", Expect: ExpectAllow}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != ERROR {
		t.Fatalf("got %s, want ERROR: a failed positive control means the probe is broken", got.Outcomes[0].Verdict)
	}
}

func TestRunRepeated_IdenticalRunsAreStable(t *testing.T) {
	noGap(t)
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Second)},
		events: []FirewallEvent{{Time: start, RuleID: "SEG-DENY-1", Action: "DROP", SrcIP: "10.0.0.c", DstIP: "10.0.0.s", DstPort: 8443, Proto: "tcp"}},
		fwOK:   true,
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	runs, stable, err := RunRepeated(context.Background(), p, s, 3)
	if err != nil || len(runs) != 3 || !stable {
		t.Fatalf("runs=%d stable=%v err=%v", len(runs), stable, err)
	}
}

// seqProvider returns a scripted sequence of probe outcomes, one per call.
type seqProvider struct {
	fakeProvider
	outcomes []Outcome
	n        int
}

func (s *seqProvider) Probe(_ context.Context, _ ProbeRequest) (ProbeResult, error) {
	o := s.outcomes[s.n%len(s.outcomes)]
	s.n++
	start := time.Unix(int64(100+s.n), 0)
	return ProbeResult{Outcome: o, Start: start, End: start.Add(time.Second)}, nil
}

func TestRunRepeated_DifferentVerdictsAcrossRunsIsUnstable(t *testing.T) {
	noGap(t)
	p := &seqProvider{
		fakeProvider: fakeProvider{fwOK: true},
		outcomes:     []Outcome{OutcomeTimeout, OutcomeConnected},
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	_, stable, err := RunRepeated(context.Background(), p, s, 2)
	if err != nil {
		t.Fatalf("RunRepeated: %v", err)
	}
	if stable {
		t.Fatal("verdicts changed between runs (PASS then FAIL); stable must be false")
	}
}

// lateProvider returns no firewall records on the first read and the record on
// the second: the collector flushes asynchronously, so a read right after the
// probe can miss evidence that arrives a moment later.
type lateProvider struct {
	fakeProvider
	calls int
	late  []FirewallEvent
}

func (l *lateProvider) FirewallEvents(_ context.Context, _ TimeWindow) ([]FirewallEvent, bool, error) {
	l.calls++
	if l.calls < 2 {
		return nil, true, nil
	}
	return l.late, true, nil
}

func TestRunScenario_LateFirewallRecordIsFound(t *testing.T) {
	noGap(t)
	start := time.Unix(100, 0)
	p := &lateProvider{
		fakeProvider: fakeProvider{result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Second)}},
		late:         []FirewallEvent{{Time: start, RuleID: "SEG-DENY-SWIFT-1", Action: "DROP", SrcIP: "10.0.0.c", DstIP: "10.0.0.s", DstPort: 8443, Proto: "tcp"}},
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != PASS {
		t.Fatalf("got %s (%s), want PASS: the record arrived after the first read", got.Outcomes[0].Verdict, got.Outcomes[0].Reason)
	}
}

// noGap removes the inter-probe gap for a unit test and restores it afterwards.
func noGap(t *testing.T) {
	t.Helper()
	old := probeGap
	probeGap = 0
	t.Cleanup(func() { probeGap = old })
}

// The executor must space consecutive probes by probeGap; without the gap, one
// probe's firewall records can fall in the next probe's evidence window.
func TestRunScenario_SpacesProbesByProbeGap(t *testing.T) {
	old := probeGap
	probeGap = 100 * time.Millisecond
	t.Cleanup(func() { probeGap = old })
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Millisecond)},
		events: []FirewallEvent{{Time: start, RuleID: "SEG-DENY-1", Action: "DROP", SrcIP: "10.0.0.c", DstIP: "10.0.0.s", DstPort: 8443, Proto: "tcp"}},
		fwOK:   true,
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{
		{ID: "a", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny},
		{ID: "b", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny},
		{ID: "c", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny},
	}}
	began := time.Now()
	if _, err := RunScenario(context.Background(), p, s, 0); err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if elapsed := time.Since(began); elapsed < 2*probeGap {
		t.Fatalf("3 probes took %s; want at least %s of gaps", elapsed, 2*probeGap)
	}
}

// flakyProvider fails the first firewall read (a half-written record, say) and
// returns the record on the second read.
type flakyProvider struct {
	fakeProvider
	calls int
	late  []FirewallEvent
}

func (f *flakyProvider) FirewallEvents(_ context.Context, _ TimeWindow) ([]FirewallEvent, bool, error) {
	f.calls++
	if f.calls == 1 {
		return nil, false, errors.New("half-written record")
	}
	return f.late, true, nil
}

func TestRunScenario_TransientLogReadErrorIsRetried(t *testing.T) {
	noGap(t)
	start := time.Unix(100, 0)
	p := &flakyProvider{
		fakeProvider: fakeProvider{result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Second)}},
		late:         []FirewallEvent{{Time: start, RuleID: "SEG-DENY-SWIFT-1", Action: "DROP", SrcIP: "10.0.0.c", DstIP: "10.0.0.s", DstPort: 8443, Proto: "tcp"}},
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != PASS {
		t.Fatalf("got %s (%s), want PASS after a retry", got.Outcomes[0].Verdict, got.Outcomes[0].Reason)
	}
}

func TestRunScenario_CancelledDuringLastProbeReturnsError(t *testing.T) {
	noGap(t)
	ctx, cancel := context.WithCancel(context.Background())
	p := &cancellingProvider{cancel: cancel}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	if _, err := RunScenario(ctx, p, s, 0); err == nil {
		t.Fatal("want an error: the run was cancelled, so its last probe must not be reported as a result")
	}
}

// cancellingProvider cancels the run while its probe is in flight.
type cancellingProvider struct {
	fakeProvider
	cancel context.CancelFunc
}

func (c *cancellingProvider) Probe(_ context.Context, _ ProbeRequest) (ProbeResult, error) {
	c.cancel()
	return ProbeResult{}, errors.New("interrupted")
}
