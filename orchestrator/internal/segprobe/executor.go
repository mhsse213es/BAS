package segprobe

import (
	"context"
	"fmt"
	"time"
)

// probeTimeout is the connection deadline each probe runner enforces.
const probeTimeout = 3 * time.Second

// evidenceWait bounds how long the executor waits for a firewall record that
// has not reached the log yet. The collector flushes asynchronously, so a read
// right after the probe can miss a record that arrives a moment later.
var evidenceWait = 3 * time.Second

// probeGap is the quiet time between consecutive probes, including the first
// probe of each repeated run. The evidence window is the probe time plus or
// minus evidenceSlack, so with a gap longer than that, one probe's firewall
// records cannot fall inside the next probe's window and be credited to it.
var probeGap = 3 * time.Second

// evidencePollInterval is the pause between reads while waiting.
var evidencePollInterval = 250 * time.Millisecond

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
	for i, spec := range s.Probes {
		if i > 0 {
			if err := sleepCtx(ctx, probeGap); err != nil {
				return RunResult{}, err
			}
		}
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

	events, available := readEvidence(ctx, p, req, res)

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

// RunRepeated runs the scenario `runs` times in sequence. stable is true only
// when every probe got the same verdict in every run; a changing verdict is a
// lab or measurement problem and must be reported, not averaged away.
func RunRepeated(ctx context.Context, p Provider, s Scenario, runs int) ([]RunResult, bool, error) {
	if runs < 1 {
		return nil, false, fmt.Errorf("runs must be at least 1, got %d", runs)
	}
	out := make([]RunResult, 0, runs)
	for i := 0; i < runs; i++ {
		if i > 0 {
			if err := sleepCtx(ctx, probeGap); err != nil {
				return nil, false, err
			}
		}
		r, err := RunScenario(ctx, p, s, i)
		if err != nil {
			return nil, false, err
		}
		out = append(out, r)
	}
	first := map[string]Verdict{}
	for _, o := range out[0].Outcomes {
		first[o.Spec.ID] = o.Verdict
	}
	stable := true
	for _, r := range out[1:] {
		for _, o := range r.Outcomes {
			if first[o.Spec.ID] != o.Verdict {
				stable = false
			}
		}
	}
	return out, stable, nil
}

// readEvidence returns the firewall events that match this probe and whether
// the firewall log was readable. It polls while the log is readable and no
// matching record exists yet, up to evidenceWait. An unreadable log is never
// retried: the caller must grade that as UNKNOWN at once. A matching record
// found late counts; a record that never arrives stays absent, so the verdict
// is still UNKNOWN and never PASS.
func readEvidence(ctx context.Context, p Provider, req ProbeRequest, res ProbeResult) ([]FirewallEvent, bool) {
	deadline := time.Now().Add(evidenceWait)
	for {
		window := TimeWindow{From: res.Start.Add(-evidenceSlack), To: res.End.Add(evidenceSlack)}
		all, available, err := p.FirewallEvents(ctx, window)
		if err != nil || !available {
			return nil, false
		}
		events := MatchEvidence(req, res, all, evidenceSlack)
		if len(events) > 0 || !time.Now().Before(deadline) {
			return events, true
		}
		select {
		case <-ctx.Done():
			return events, true
		case <-time.After(evidencePollInterval):
		}
	}
}

// sleepCtx waits for d or until ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
