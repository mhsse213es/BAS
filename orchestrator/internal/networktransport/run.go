package networktransport

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

const (
	MaxChecksPerRun     = 50
	DefaultCheckTimeout = 5 * time.Second
	MaxCheckTimeout     = 10 * time.Second
	maxConcurrency      = 10
)

// MaxRunDuration is a var, not a const, so tests can shorten it.
var MaxRunDuration = 60 * time.Second

type CheckType string

const (
	CheckCleartext CheckType = "cleartext"
	CheckCert      CheckType = "cert"
)

type TransportCheckRequest struct {
	CheckType CheckType           `json:"checkType"`
	Target    networkgraph.Target `json:"target"`
}

type RunStatus string

const (
	RunCompleted RunStatus = "completed"
	RunPartial   RunStatus = "partial"
)

type RunResult struct {
	Status  RunStatus
	Results []networksecurity.SecurityCheckResult
}

// RunChecks executes every check with bounded concurrency, isolating
// one check's failure from every other -- mirrors
// networkgraph.RunDiscovery's and networkdns.RunChecks's own isolation
// guarantee.
func RunChecks(ctx context.Context, cleartextProbe CleartextProbe, certProbe CertProbe, vp networkgraph.VantagePoint, checks []TransportCheckRequest) (*RunResult, error) {
	if len(checks) == 0 {
		return nil, fmt.Errorf("networktransport: RunChecks requires at least one check")
	}
	if len(checks) > MaxChecksPerRun {
		return nil, fmt.Errorf("networktransport: too many checks -- got %d, max %d", len(checks), MaxChecksPerRun)
	}

	runCtx, cancel := context.WithTimeout(ctx, MaxRunDuration)
	defer cancel()

	results := make([]networksecurity.SecurityCheckResult, len(checks))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func(i int, check TransportCheckRequest) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-runCtx.Done():
				results[i] = deadlineExceededResult(check)
				return
			}
			results[i] = runOneCheck(runCtx, cleartextProbe, certProbe, check)
		}(i, check)
	}
	wg.Wait()

	status := RunCompleted
	if runCtx.Err() != nil {
		status = RunPartial
	}
	return &RunResult{Status: status, Results: results}, nil
}

func runOneCheck(ctx context.Context, cleartextProbe CleartextProbe, certProbe CertProbe, check TransportCheckRequest) networksecurity.SecurityCheckResult {
	var state networksecurity.SecurityState
	var reason string
	switch check.CheckType {
	case CheckCert:
		state, reason = certProbe.Probe(ctx, check.Target, DefaultCheckTimeout)
	case CheckCleartext:
		state, reason = cleartextProbe.Probe(ctx, check.Target, DefaultCheckTimeout)
	default:
		// An unrecognized check type must never be silently routed to
		// a real probe -- the HTTP API already rejects this before it
		// reaches here, but this layer must not trust that alone.
		state = networksecurity.Unknown
		reason = fmt.Sprintf("unrecognized check type %q", check.CheckType)
	}
	return networksecurity.SecurityCheckResult{
		Target:     check.Target,
		State:      state,
		Reason:     reason,
		Provenance: cloudgraph.Provenance{ObservedAt: time.Now()},
	}
}

func deadlineExceededResult(check TransportCheckRequest) networksecurity.SecurityCheckResult {
	return networksecurity.SecurityCheckResult{
		Target: check.Target, State: networksecurity.Unknown, Reason: "run deadline exceeded before this check ran",
		Provenance: cloudgraph.Provenance{ObservedAt: time.Now()},
	}
}
