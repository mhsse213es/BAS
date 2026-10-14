package networkdns

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

const (
	MaxChecksPerRun     = 50
	DefaultCheckTimeout = 5 * time.Second
	MaxCheckTimeout     = 10 * time.Second
	maxConcurrency      = 10
)

// MaxRunDuration is a var, not a const, so tests can shorten it --
// mirrors networkgraph.MaxRunDuration's exact reason.
var MaxRunDuration = 60 * time.Second

type CheckType string

const (
	CheckOpenResolver CheckType = "open-resolver"
	CheckDNSSEC       CheckType = "dnssec"
)

// DNSCheckRequest declares one check. Target is required for
// CheckOpenResolver and ignored for CheckDNSSEC (DNSSEC validation
// resolves the chain itself starting from the root trust anchor).
type DNSCheckRequest struct {
	CheckType   CheckType           `json:"checkType"`
	Target      networkgraph.Target `json:"target,omitempty"`
	QueryDomain string              `json:"queryDomain"`
}

// DNSCheckResult is a tagged union: exactly one of Observation/DNSSEC is
// populated, selected by CheckType.
type DNSCheckResult struct {
	CheckType   CheckType                        `json:"checkType"`
	Observation *networkgraph.NetworkObservation `json:"observation,omitempty"`
	DNSSEC      *DNSSECResult                    `json:"dnssec,omitempty"`
}

type RunStatus string

const (
	RunCompleted RunStatus = "completed"
	RunPartial   RunStatus = "partial"
)

type RunResult struct {
	Status  RunStatus
	Results []DNSCheckResult
}

// RunChecks executes every check with bounded concurrency, isolating
// one check's failure from every other -- mirrors
// networkgraph.RunDiscovery's own isolation guarantee.
func RunChecks(ctx context.Context, probe OpenResolverProbe, vp networkgraph.VantagePoint, checks []DNSCheckRequest) (*RunResult, error) {
	if len(checks) == 0 {
		return nil, fmt.Errorf("networkdns: RunChecks requires at least one check")
	}
	if len(checks) > MaxChecksPerRun {
		return nil, fmt.Errorf("networkdns: too many checks -- got %d, max %d", len(checks), MaxChecksPerRun)
	}

	runCtx, cancel := context.WithTimeout(ctx, MaxRunDuration)
	defer cancel()

	results := make([]DNSCheckResult, len(checks))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func(i int, check DNSCheckRequest) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-runCtx.Done():
				results[i] = deadlineExceededResult(check)
				return
			}
			results[i] = runOneCheck(runCtx, probe, vp, check)
		}(i, check)
	}
	wg.Wait()

	status := RunCompleted
	if runCtx.Err() != nil {
		status = RunPartial
	}
	return &RunResult{Status: status, Results: results}, nil
}

func runOneCheck(ctx context.Context, probe OpenResolverProbe, vp networkgraph.VantagePoint, check DNSCheckRequest) DNSCheckResult {
	switch check.CheckType {
	case CheckDNSSEC:
		dnssec := ValidateDNSSEC(ctx, check.QueryDomain)
		return DNSCheckResult{CheckType: CheckDNSSEC, DNSSEC: &dnssec}
	default: // CheckOpenResolver
		state, probeErr := probe.Probe(ctx, check.Target, check.QueryDomain, DefaultCheckTimeout)
		errDetail := ""
		if probeErr != nil {
			errDetail = probeErr.Error()
		}
		obs := networkgraph.NetworkObservation{
			Target:         check.Target,
			VantagePointID: vp.ID,
			State:          state,
			ErrorDetail:    errDetail,
			Provenance:     cloudgraph.Provenance{Source: vp.NetworkPosition, ObservedAt: time.Now()},
		}
		return DNSCheckResult{CheckType: CheckOpenResolver, Observation: &obs}
	}
}

func deadlineExceededResult(check DNSCheckRequest) DNSCheckResult {
	if check.CheckType == CheckDNSSEC {
		return DNSCheckResult{CheckType: CheckDNSSEC, DNSSEC: &DNSSECResult{
			Domain: check.QueryDomain, State: DNSSECUnknown, Reason: "run deadline exceeded before this check ran",
			Provenance: cloudgraph.Provenance{ObservedAt: time.Now()},
		}}
	}
	return DNSCheckResult{CheckType: CheckOpenResolver, Observation: &networkgraph.NetworkObservation{
		Target: check.Target, State: cloudgraph.Unknown, ErrorDetail: "run deadline exceeded before this check ran",
		Provenance: cloudgraph.Provenance{ObservedAt: time.Now(), Confidence: "none"},
	}}
}
