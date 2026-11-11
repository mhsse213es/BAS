package segprobe

import (
	"context"
	"fmt"
	"time"
)

// probeTimeout is the connection deadline each probe runner enforces.
const probeTimeout = 3 * time.Second

// evidenceSlack widens the probe window when matching firewall events, to
// absorb clock skew between the probe runner and the firewall.
const evidenceSlack = 2 * time.Second

type ProbeOutcome struct {
	Spec    ProbeSpec
	Verdict Verdict
	Reason  string
	Result  ProbeResult
	Events  []FirewallEvent
}

type RunResult struct {
	ScenarioID string
	RunIndex   int
	Outcomes   []ProbeOutcome
}

// RunScenario performs one pass over every probe in the scenario. A transport
// or lookup failure is recorded as an ERROR outcome for that probe; only a
// cancelled context aborts the whole pass.
func RunScenario(ctx context.Context, p Provider, s Scenario, runIndex int) (RunResult, error) {
	out := RunResult{ScenarioID: s.ID, RunIndex: runIndex}
	for _, spec := range s.Probes {
		if err := ctx.Err(); err != nil {
			return RunResult{}, err
		}
		out.Outcomes = append(out.Outcomes, runProbe(ctx, p, spec))
	}
	return out, nil
}

func runProbe(ctx context.Context, p Provider, spec ProbeSpec) ProbeOutcome {
	errOutcome := func(reason string) ProbeOutcome {
		return ProbeOutcome{Spec: spec, Verdict: ERROR, Reason: reason}
	}

	for _, z := range []Zone{spec.Src, spec.Dst} {
		if err := p.Healthy(ctx, z); err != nil {
			return errOutcome(fmt.Sprintf("destination or probe unavailable: zone %s: %v", z, err))
		}
	}
	srcIP, err := p.Lookup(spec.Src)
	if err != nil {
		return errOutcome(fmt.Sprintf("lookup source zone %s: %v", spec.Src, err))
	}
	dstIP, err := p.Lookup(spec.Dst)
	if err != nil {
		return errOutcome(fmt.Sprintf("lookup destination zone %s: %v", spec.Dst, err))
	}

	req := ProbeRequest{
		SrcZone: string(spec.Src),
		DstZone: string(spec.Dst),
		SrcIP:   srcIP,
		DstIP:   dstIP,
		DstPort: spec.DstPort,
		Proto:   spec.Proto,
		Timeout: probeTimeout,
		Expect:  spec.Expect,
	}
	res, err := p.Probe(ctx, req)
	if err != nil {
		return errOutcome(fmt.Sprintf("probe execution failed: %v", err))
	}

	window := TimeWindow{From: res.Start.Add(-evidenceSlack), To: res.End.Add(evidenceSlack)}
	all, available, err := p.FirewallEvents(ctx, window)
	if err != nil {
		available = false
	}
	events := MatchEvidence(req, res, all, evidenceSlack)

	verdict, reason := Evaluate(spec.Expect, Evidence{
		ProbeResult:       res,
		Events:            events,
		FirewallAvailable: available,
	})
	return ProbeOutcome{Spec: spec, Verdict: verdict, Reason: reason, Result: res, Events: events}
}
