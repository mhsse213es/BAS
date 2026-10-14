package networkgraph

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

const (
	// MaxTargetsPerRun bounds blast radius -- a request exceeding this is
	// rejected before any probing starts.
	MaxTargetsPerRun = 50
	// DefaultProbeTimeout applies when a caller doesn't specify one.
	DefaultProbeTimeout = 2 * time.Second
	// MaxProbeTimeout is the ceiling a caller-requested timeout may not
	// exceed -- a request above this is rejected, never silently clamped.
	MaxProbeTimeout = 5 * time.Second
	// maxConcurrency is fixed, never caller-configurable in this phase.
	maxConcurrency = 10
)

// MaxRunDuration is the whole-run wall-clock deadline. It is a var, not a
// const, so tests can shorten it to exercise the deadline-exceeded path
// without waiting 30 real seconds; production code never changes it.
var MaxRunDuration = 30 * time.Second

// DiscoveryOptions configures one RunDiscovery call.
type DiscoveryOptions struct {
	// TimeoutPerTarget, if zero, defaults to DefaultProbeTimeout. A value
	// above MaxProbeTimeout is rejected by RunDiscovery itself (defense in
	// depth -- the HTTP layer also rejects it before calling this).
	TimeoutPerTarget time.Duration
}

// RunStatus is the discovery run's own completion state -- distinct from
// any individual target's PathState.
type RunStatus string

const (
	// RunCompleted means every target was probed within the run deadline,
	// regardless of each target's own classification.
	RunCompleted RunStatus = "completed"
	// RunPartial means MaxRunDuration was reached before every target was
	// probed; the remainder are recorded Unknown with an explicit
	// deadline-exceeded note, never dropped.
	RunPartial RunStatus = "partial"
)

// DiscoveryResult is RunDiscovery's output: one NetworkObservation and one
// NetworkFinding per requested target, in the same order as targets, plus
// the run's own completion status.
type DiscoveryResult struct {
	Status       RunStatus
	Observations []NetworkObservation
	Findings     []NetworkFinding
}

// RunDiscovery probes every target with bounded concurrency (maxConcurrency
// workers) -- never sequentially, since a sequential pass over
// MaxTargetsPerRun targets at MaxProbeTimeout each could take minutes. One
// target's probe error never prevents any other target's probe from
// running or being recorded (isolation).
func RunDiscovery(ctx context.Context, probe TCPReachabilityProbe, vp VantagePoint, targets []Target, opts DiscoveryOptions) (*DiscoveryResult, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("networkgraph: RunDiscovery requires at least one target")
	}
	if len(targets) > MaxTargetsPerRun {
		return nil, fmt.Errorf("networkgraph: too many targets -- got %d, max %d", len(targets), MaxTargetsPerRun)
	}
	timeout := opts.TimeoutPerTarget
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	if timeout > MaxProbeTimeout {
		return nil, fmt.Errorf("networkgraph: timeoutPerTarget %s exceeds max %s", timeout, MaxProbeTimeout)
	}

	runCtx, cancel := context.WithTimeout(ctx, MaxRunDuration)
	defer cancel()

	observations := make([]NetworkObservation, len(targets))
	findings := make([]NetworkFinding, len(targets))

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-runCtx.Done():
				observations[i] = deadlineExceededObservation(vp, target)
				findings[i] = NetworkFinding{Target: target, State: cloudgraph.Unknown, Limitations: deadlineLimitation}
				return
			}

			state, probeErr := probe.Probe(runCtx, target, timeout)
			errDetail := ""
			if probeErr != nil {
				errDetail = probeErr.Error()
			}
			observations[i] = NetworkObservation{
				Target:         target,
				VantagePointID: vp.ID,
				State:          state,
				ErrorDetail:    errDetail,
				Provenance: cloudgraph.Provenance{
					Source:     vp.NetworkPosition,
					ObservedAt: time.Now(),
					Confidence: confidenceFor(state),
				},
			}
			findings[i] = NetworkFinding{Target: target, State: state, Limitations: limitationsFor(state)}
		}(i, target)
	}
	wg.Wait()

	status := RunCompleted
	if runCtx.Err() != nil {
		status = RunPartial
	}
	return &DiscoveryResult{Status: status, Observations: observations, Findings: findings}, nil
}

const deadlineLimitation = "run deadline exceeded before this target was probed"

func deadlineExceededObservation(vp VantagePoint, target Target) NetworkObservation {
	return NetworkObservation{
		Target:         target,
		VantagePointID: vp.ID,
		State:          cloudgraph.Unknown,
		ErrorDetail:    deadlineLimitation,
		Provenance: cloudgraph.Provenance{
			Source:     vp.NetworkPosition,
			ObservedAt: time.Now(),
			Confidence: "none",
		},
	}
}

func confidenceFor(state cloudgraph.PathState) string {
	switch state {
	case cloudgraph.Observed, cloudgraph.Blocked:
		return "high"
	default:
		return "low"
	}
}

func limitationsFor(state cloudgraph.PathState) string {
	if state == cloudgraph.Unknown {
		return "a timeout or inconclusive probe result is not proof of a firewall block"
	}
	return ""
}
