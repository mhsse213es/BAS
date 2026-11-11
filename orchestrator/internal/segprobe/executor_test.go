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
func (f *fakeProvider) Probe(_ context.Context, _ ProbeRequest) (ProbeResult, error) {
	return f.result, f.probeErr
}
func (f *fakeProvider) FirewallEvents(_ context.Context, _ TimeWindow) ([]FirewallEvent, bool, error) {
	return f.events, f.fwOK, f.fwErr
}

func TestRunScenario_DestinationDown_IsError(t *testing.T) {
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
