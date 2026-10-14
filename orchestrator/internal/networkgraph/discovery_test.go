package networkgraph

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

// fakeProbe is a deterministic, injectable TCPReachabilityProbe for
// testing RunDiscovery's orchestration logic without any real sockets.
type fakeProbe struct {
	mu      sync.Mutex
	active  int
	maxSeen int
	results map[string]fakeResult
	delay   time.Duration
}

type fakeResult struct {
	state cloudgraph.PathState
	err   error
}

func (f *fakeProbe) Probe(ctx context.Context, target Target, timeout time.Duration) (cloudgraph.PathState, error) {
	f.mu.Lock()
	f.active++
	if f.active > f.maxSeen {
		f.maxSeen = f.active
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return cloudgraph.Unknown, ctx.Err()
		}
	}

	key := fmt.Sprintf("%s:%d", target.Host, target.Port)
	f.mu.Lock()
	r, ok := f.results[key]
	f.mu.Unlock()
	if ok {
		return r.state, r.err
	}
	return cloudgraph.Unknown, fmt.Errorf("fakeProbe: no canned result for %s", key)
}

func testVP() VantagePoint { return VantagePoint{ID: "vp-1", NetworkPosition: "test-position"} }

func TestRunDiscovery_ObservedAndBlockedResultsAreIsolated(t *testing.T) {
	fp := &fakeProbe{results: map[string]fakeResult{
		"10.0.0.1:443": {state: cloudgraph.Observed},
		"10.0.0.2:443": {state: cloudgraph.Blocked, err: fmt.Errorf("connection refused")},
	}}
	targets := []Target{
		{Host: "10.0.0.1", Port: 443},
		{Host: "10.0.0.2", Port: 443},
	}

	result, err := RunDiscovery(context.Background(), fp, testVP(), targets, DiscoveryOptions{})
	if err != nil {
		t.Fatalf("RunDiscovery: %v", err)
	}
	if result.Status != RunCompleted {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if result.Findings[0].State != cloudgraph.Observed {
		t.Errorf("target 0 state = %q, want observed", result.Findings[0].State)
	}
	if result.Findings[1].State != cloudgraph.Blocked {
		t.Errorf("target 1 state = %q, want blocked", result.Findings[1].State)
	}
}

func TestRunDiscovery_RejectsEmptyTargets(t *testing.T) {
	_, err := RunDiscovery(context.Background(), &fakeProbe{}, testVP(), nil, DiscoveryOptions{})
	if err == nil {
		t.Fatal("want error for zero targets")
	}
}

func TestRunDiscovery_RejectsTooManyTargets(t *testing.T) {
	targets := make([]Target, MaxTargetsPerRun+1)
	for i := range targets {
		targets[i] = Target{Host: "10.0.0.1", Port: 443}
	}
	_, err := RunDiscovery(context.Background(), &fakeProbe{}, testVP(), targets, DiscoveryOptions{})
	if err == nil {
		t.Fatal("want error for too many targets")
	}
}

func TestRunDiscovery_RejectsTimeoutAboveMax(t *testing.T) {
	_, err := RunDiscovery(context.Background(), &fakeProbe{}, testVP(),
		[]Target{{Host: "10.0.0.1", Port: 443}}, DiscoveryOptions{TimeoutPerTarget: MaxProbeTimeout + time.Second})
	if err == nil {
		t.Fatal("want error for timeout above max")
	}
}

func TestRunDiscovery_BoundedConcurrencyNeverExceedsLimit(t *testing.T) {
	fp := &fakeProbe{delay: 20 * time.Millisecond, results: map[string]fakeResult{}}
	targets := make([]Target, MaxTargetsPerRun)
	for i := range targets {
		host := fmt.Sprintf("10.0.0.%d", i)
		targets[i] = Target{Host: host, Port: 443}
		fp.results[fmt.Sprintf("%s:443", host)] = fakeResult{state: cloudgraph.Observed}
	}

	_, err := RunDiscovery(context.Background(), fp, testVP(), targets, DiscoveryOptions{})
	if err != nil {
		t.Fatalf("RunDiscovery: %v", err)
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if fp.maxSeen > maxConcurrency {
		t.Fatalf("observed concurrency %d, want <= %d", fp.maxSeen, maxConcurrency)
	}
}

// TestRunDiscovery_PartialStatusWhenRunDeadlineExceeded proves the one
// branch unlikely to be reachable through any of this plan's other,
// fast-fixture tests: a run that cannot finish every target within
// MaxRunDuration must report RunPartial, and every target that didn't get
// probed in time must be recorded Unknown with a non-empty Limitations
// note -- never silently dropped.
func TestRunDiscovery_PartialStatusWhenRunDeadlineExceeded(t *testing.T) {
	old := MaxRunDuration
	MaxRunDuration = 30 * time.Millisecond
	defer func() { MaxRunDuration = old }()

	fp := &fakeProbe{delay: 500 * time.Millisecond, results: map[string]fakeResult{}}
	targets := make([]Target, MaxTargetsPerRun)
	for i := range targets {
		host := fmt.Sprintf("10.0.0.%d", i)
		targets[i] = Target{Host: host, Port: 443}
		fp.results[fmt.Sprintf("%s:443", host)] = fakeResult{state: cloudgraph.Observed}
	}

	result, err := RunDiscovery(context.Background(), fp, testVP(), targets, DiscoveryOptions{})
	if err != nil {
		t.Fatalf("RunDiscovery: %v", err)
	}
	if result.Status != RunPartial {
		t.Fatalf("status = %q, want partial", result.Status)
	}
	foundUnknownWithNote := false
	for _, f := range result.Findings {
		if f.State == cloudgraph.Unknown && f.Limitations != "" {
			foundUnknownWithNote = true
		}
	}
	if !foundUnknownWithNote {
		t.Fatal("want at least one finding recorded Unknown with a limitations note when the run deadline is exceeded")
	}
	if len(result.Findings) != MaxTargetsPerRun {
		t.Fatalf("findings count = %d, want %d -- no target may be dropped even when the run deadline is exceeded", len(result.Findings), MaxTargetsPerRun)
	}
}

func TestRunDiscovery_DuplicateTargetsAreEachProbedAndReportedIndependently(t *testing.T) {
	fp := &fakeProbe{results: map[string]fakeResult{"10.0.0.1:443": {state: cloudgraph.Observed}}}
	targets := []Target{
		{Host: "10.0.0.1", Port: 443},
		{Host: "10.0.0.1", Port: 443},
	}

	result, err := RunDiscovery(context.Background(), fp, testVP(), targets, DiscoveryOptions{})
	if err != nil {
		t.Fatalf("RunDiscovery: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings count = %d, want 2 -- duplicate targets are not deduplicated in this phase", len(result.Findings))
	}
	for i, f := range result.Findings {
		if f.State != cloudgraph.Observed {
			t.Errorf("finding %d state = %q, want observed", i, f.State)
		}
	}
}
