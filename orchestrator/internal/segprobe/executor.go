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
	dstIP, err := p.TargetIP(spec.Dst)
	if err != nil {
		return errOutcome(fmt.Sprintf("target address for zone %s: %v", spec.Dst, err))
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

	// Same-zone traffic never crosses seg-fw, so no firewall evidence exists
	// and none is required. Its verdict rests on the connection alone.
	if spec.Src == spec.Dst {
		return sameZoneOutcome(spec, res)
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

// sameZoneOutcome grades a same-zone positive control. Only an allow probe is
// valid here (the loader enforces it). A connection that fails means the
// control itself is broken, so the result is ERROR, not a segmentation finding.
func sameZoneOutcome(spec ProbeSpec, res ProbeResult) ProbeOutcome {
	if res.Outcome == OutcomeConnected {
		return ProbeOutcome{Spec: spec, Verdict: PASS, Result: res,
			Reason: "same-zone reachability confirmed; no firewall crossing"}
	}
	return ProbeOutcome{Spec: spec, Verdict: ERROR, Result: res,
		Reason: fmt.Sprintf("same-zone positive control failed: %s", res.Outcome)}
}
