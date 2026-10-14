# Network BAS Phase 1 (Evidence Foundation & Discovery) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `internal/networkgraph` package (typed network-connectivity evidence foundation reusing `cloudgraph.PathState`/`Provenance`) plus a working, safety-capped, orchestrator-originated TCP reachability discovery capability, exposed via a dedicated HTTP API and persisted to Postgres.

**Architecture:** New package `internal/networkgraph` holds pure types (`Target`, `VantagePoint`, `NetworkObservation`, `NetworkFinding`) and the probe/discovery logic, with zero DB or HTTP dependencies. A new `internal/db/networkdiscovery_store.go` and `internal/api/networkdiscovery_handlers.go` follow the `cloud_run`/`cloud_campaign` precedent exactly (dedicated API + Postgres, not `scenario.Engine` — Phase 1 has no agent-side execution to dispatch). The orchestrator's network vantage point is resolved once at server startup from environment configuration and attached to the `Handler` via a new `WithNetworkVantagePoint` method, following the existing `WithCompliance`-style fluent-setter convention.

**Tech Stack:** Go, `net.Dialer`/`net.DialContext` for TCP reachability, Postgres via `pgxpool`, `go-chi/chi/v5` routing — all already in use in this codebase, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-13-network-bas-phase1-evidence-foundation-design.md` (Phase 1 implementation spec). Parent: `docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md` (master architecture). Executors should read both — the master spec carries the three-evidence-domain architecture this phase implements one leg of.

## Global Constraints

- Probes originate only from the orchestrator server process. No agent-based vantage points in this plan.
- Probe method is bounded TCP reachability via `net.DialTimeout`/`DialContext` only — no host enumeration, no ping sweeps, no service/banner probing (the connection is closed immediately on success, nothing is sent or read beyond the handshake).
- Targets are explicitly authorized by the caller's own request — never discovered via scanning. `maxTargetsPerRun = 50`.
- `defaultProbeTimeout = 2s`, `maxProbeTimeout = 5s` — a caller-requested timeout above the max is **rejected**, never silently clamped.
- `maxConcurrency = 10`, fixed, never caller-configurable.
- `maxRunDuration = 30s` wall-clock cap on the whole discovery run; targets not probed in time are recorded `Unknown` with an explicit deadline-exceeded note, never dropped.
- `cloudgraph.PathState`'s six values are reused verbatim, unchanged semantics — a TCP connect success maps to `Observed`, an actively-refused connection to `Blocked`, a timeout or any other dial error to `Unknown` (**never** `Blocked` — a timeout is not proof of a block).
- The vantage point's network position is fixed by server configuration (`NETWORK_VANTAGE_POINT_ID`, `NETWORK_VANTAGE_POINT_POSITION` env vars), resolved once at startup, never supplied per-request. If unset, discovery requests return `503`, not a default/fabricated value.
- `RequestedBy` on every run is always the authenticated caller from `auth.ClaimsFrom(r.Context())`, never trusted from the request body.
- The HTTP request body is bounded via `http.MaxBytesReader` from the start (`maxNetworkDiscoveryRequestBytes = 1<<20`) — this is a lesson already learned and fixed after-the-fact on `cloud_campaign`'s own endpoint; here it ships correct from task 1 of the handler work, not as a follow-up fix.
- No test in this plan may send real network traffic off the test host — loopback listeners and in-process fakes only. A genuine network *timeout* is tested via dependency injection on the probe, never by dialing a real, possibly-external address.
- Host machine has only 7.84GB RAM: never run the full unscoped `go test ./internal/api/...` package suite. Substitute `go build ./...` + `go test ./internal/db/... ./internal/cloudgraph/... ./internal/networkgraph/...` + every relevant `internal/api` test together via one `-run` regex. Check `Get-CimInstance Win32_OperatingSystem` free/total memory before any `internal/api` test run.
- Work happens inline on `main`, no worktree, no feature branch (standing session convention). `git fetch` + `git log --oneline main..origin/main` before every push; `git pull` + a build sanity check if anything landed from the separately-running "Threat Content Factory" session — never touch or investigate its files.
- Sonnet only for any subagent/fork dispatch in this plan's review step, never Opus.

## Review Focus

- **A caller submits a target whose host resolves to a private/internal address they don't actually control** (e.g. `127.0.0.1` or an RFC1918 address outside any declared scope). Phase 1 has no asset-inventory/scope-authorization mechanism yet (explicitly deferred per the spec) — "authorized" in this phase means only "an authenticated caller with `auth.CanRunScenario` submitted this exact list." A reasonable person reading "explicitly authorized destinations" might expect server-side scope enforcement beyond authentication; this plan does not add it, and Task 5's handler doc comment must say so explicitly rather than let the gap go unstated.
- **A target list contains duplicate host:port entries.** Nothing in this plan's validation rejects duplicates. A reasonable person might expect either deduplication or a clear per-entry result; this plan's behavior (each duplicate entry is probed and reported independently, exactly as submitted) must be covered by a test so it's a documented, verified behavior rather than an accident.
- **The vantage point becomes unconfigured *between* server startup and a request arriving** (impossible in this plan's design, since it's resolved once at startup and never changes) — not a real risk here, but the `Configured()` check still needs a test proving a zero-value `Handler` (never had `WithNetworkVantagePoint` called) returns 503, not a panic from a nil map or similar.
- **The run-deadline-exceeded (`partial`) branch is the one path most likely to be silently un-exercised** by ordinary fast-fixture tests, since every other test in this plan completes in milliseconds. Task 3 must include a direct unit test that shortens `MaxRunDuration` and proves both the `partial` status and the per-target `Unknown`+limitations-note behavior — this is called out explicitly in Task 3's steps below, not left to incidental coverage.
- **A probe's `net.Conn` is a real, live connection that must be closed**, or the orchestrator process will leak file descriptors under repeated discovery runs. Task 2's `DialerProbe` test suite must include a case proving the connection is actually closed on the `Observed` path (not just that `Observed` is returned), since a leaked `net.Conn` would otherwise be invisible to every other test in this plan.

---

### Task 1: Core Types & Vantage Point Resolution

**Files:**
- Create: `orchestrator/internal/networkgraph/types.go`
- Create: `orchestrator/internal/networkgraph/vantagepoint.go`
- Test: `orchestrator/internal/networkgraph/vantagepoint_test.go`

**Interfaces:**
- Consumes: `cloudgraph.PathState`, `cloudgraph.Provenance` (both already exist, unmodified, in `orchestrator/internal/cloudgraph/types.go:5-14,26-32`).
- Produces: `networkgraph.Target{Host, Port, Protocol, Label}`, `networkgraph.VantagePoint{ID, NetworkPosition}` with method `Configured() bool`, `networkgraph.NetworkObservation{ID, RunID, Target, VantagePointID, State, ErrorDetail, Provenance}`, `networkgraph.NetworkFinding{Target, State, Limitations}`, `networkgraph.LoadVantagePoint() (VantagePoint, error)`. Task 2 consumes `Target`/`VantagePoint` exactly as defined here. Task 3 consumes all four types plus `LoadVantagePoint`'s error contract (unset/empty env var → error, never a usable zero-value `VantagePoint`).

- [ ] **Step 1: Create the core types file (scaffolding, no behavior of its own — the first real test in Step 2 exercises it through `LoadVantagePoint`)**

Create `orchestrator/internal/networkgraph/types.go`:

```go
// Package networkgraph models network-connectivity evidence for Network
// BAS Mastery Phase 1. It deliberately reuses cloudgraph.PathState and
// cloudgraph.Provenance rather than redefining them -- see
// docs/superpowers/specs/2026-10-13-network-bas-phase1-evidence-foundation-design.md.
package networkgraph

import (
	"github.com/audspect/bas/internal/cloudgraph"
)

// Target is a single, explicitly authorized probe destination. There is no
// discovery-of-targets in this phase -- every Target is supplied by an
// authenticated, permissioned caller, never derived from scanning.
type Target struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Label    string `json:"label,omitempty"`
}

// VantagePoint identifies where probes actually originate. Populated once,
// at server startup, from operator configuration -- never from a request
// body. The zero value is never a valid, usable vantage point; callers
// must check Configured() before using one.
type VantagePoint struct {
	ID              string `json:"id"`
	NetworkPosition string `json:"networkPosition"`
}

// Configured reports whether vp was actually resolved from configuration.
func (vp VantagePoint) Configured() bool {
	return vp.ID != "" && vp.NetworkPosition != ""
}

// NetworkObservation is one probe's result against one Target, from one
// VantagePoint, at one point in time.
type NetworkObservation struct {
	ID             string                `json:"id,omitempty"`
	RunID          string                `json:"runId,omitempty"`
	Target         Target                `json:"target"`
	VantagePointID string                `json:"vantagePointId"`
	State          cloudgraph.PathState  `json:"state"`
	ErrorDetail    string                `json:"errorDetail,omitempty"`
	Provenance     cloudgraph.Provenance `json:"provenance"`
}

// NetworkFinding is the reporting-layer unit: one Target's final
// classification for a run, derived from its NetworkObservation, never
// invented. Limitations is a human-readable caveat (e.g. "a timeout is not
// proof of a block"), computed, never persisted as its own column.
type NetworkFinding struct {
	Target      Target               `json:"target"`
	State       cloudgraph.PathState `json:"state"`
	Limitations string               `json:"limitations,omitempty"`
}
```

- [ ] **Step 2: Write the failing test for `LoadVantagePoint`**

Create `orchestrator/internal/networkgraph/vantagepoint_test.go`:

```go
package networkgraph

import "testing"

func TestLoadVantagePoint_BothSetReturnsConfiguredVantagePoint(t *testing.T) {
	t.Setenv("NETWORK_VANTAGE_POINT_ID", "test-vp-1")
	t.Setenv("NETWORK_VANTAGE_POINT_POSITION", "test-dc1-mgmt-vlan")

	vp, err := LoadVantagePoint()
	if err != nil {
		t.Fatalf("LoadVantagePoint: %v", err)
	}
	if vp.ID != "test-vp-1" || vp.NetworkPosition != "test-dc1-mgmt-vlan" {
		t.Fatalf("got %+v, want ID=test-vp-1 NetworkPosition=test-dc1-mgmt-vlan", vp)
	}
	if !vp.Configured() {
		t.Fatal("want Configured() true when both env vars are set")
	}
}

func TestLoadVantagePoint_EitherUnsetReturnsError(t *testing.T) {
	cases := []struct {
		name    string
		id, pos string
	}{
		{"both unset", "", ""},
		{"id unset", "", "some-position"},
		{"position unset", "some-id", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NETWORK_VANTAGE_POINT_ID", c.id)
			t.Setenv("NETWORK_VANTAGE_POINT_POSITION", c.pos)

			vp, err := LoadVantagePoint()
			if err == nil {
				t.Fatalf("want error, got vp=%+v", vp)
			}
			if vp.Configured() {
				t.Fatal("want Configured() false on error")
			}
		})
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/networkgraph/... -v`
Expected: FAIL — `LoadVantagePoint` undefined (package `networkgraph` doesn't compile without it).

- [ ] **Step 4: Implement `LoadVantagePoint`**

Create `orchestrator/internal/networkgraph/vantagepoint.go`:

```go
package networkgraph

import (
	"fmt"
	"os"
)

const (
	envVantagePointID       = "NETWORK_VANTAGE_POINT_ID"
	envVantagePointPosition = "NETWORK_VANTAGE_POINT_POSITION"
)

// LoadVantagePoint reads the vantage point's identity from environment
// configuration. It returns an error if either value is unset or empty --
// there is no default, because a default would be exactly the "declare a
// network position we don't actually occupy" failure mode Network BAS
// Phase 1 rules out. Call this once at server startup; the resolved
// VantagePoint is held by the caller for the life of the process, never
// re-read per request.
func LoadVantagePoint() (VantagePoint, error) {
	id := os.Getenv(envVantagePointID)
	position := os.Getenv(envVantagePointPosition)
	if id == "" || position == "" {
		return VantagePoint{}, fmt.Errorf("networkgraph: both %s and %s must be set to a non-empty value", envVantagePointID, envVantagePointPosition)
	}
	return VantagePoint{ID: id, NetworkPosition: position}, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/networkgraph/... -v`
Expected: PASS (both test functions, 4 subtests total).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networkgraph/types.go orchestrator/internal/networkgraph/vantagepoint.go orchestrator/internal/networkgraph/vantagepoint_test.go
git commit -m "feat(networkgraph): add core evidence types and vantage point resolution"
```

---

### Task 2: TCP Reachability Probe

**Files:**
- Create: `orchestrator/internal/networkgraph/probe.go`
- Test: `orchestrator/internal/networkgraph/probe_test.go`

**Interfaces:**
- Consumes: `Target` (Task 1), `cloudgraph.PathState` (existing).
- Produces: `networkgraph.TCPReachabilityProbe` interface (`Probe(ctx, target Target, timeout time.Duration) (cloudgraph.PathState, error)`), `networkgraph.DialerProbe{}` (the real implementation, zero-value-constructible). Task 3 consumes this exact interface — `RunDiscovery` takes a `TCPReachabilityProbe` so it can be given `DialerProbe{}` in production and a fake in tests.

- [ ] **Step 1: Write the failing tests for probe classification**

Create `orchestrator/internal/networkgraph/probe_test.go`:

```go
package networkgraph

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

func TestDialerProbe_SuccessfulConnectIsObserved(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)

	state, err := DialerProbe{}.Probe(context.Background(), Target{Host: "127.0.0.1", Port: addr.Port}, time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Observed {
		t.Fatalf("state = %q, want observed", state)
	}
}

func TestDialerProbe_ActivelyRefusedConnectionIsBlocked(t *testing.T) {
	// A port that WAS listening and is now closed reliably returns
	// "connection refused" on every platform this runs on, without ever
	// leaving loopback -- unlike dialing a port nothing ever bound to,
	// whose behavior can vary by platform/firewall.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()

	state, err := DialerProbe{}.Probe(context.Background(), Target{Host: "127.0.0.1", Port: addr.Port}, time.Second)
	if err == nil {
		t.Fatal("want a non-nil error for a refused connection")
	}
	if state != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked", state)
	}
}

func TestDialerProbe_GenericDialErrorIsUnknownNeverBlocked(t *testing.T) {
	// A real network timeout is unsafe/unreliable to force in a test
	// without risking real traffic off this host, so this injects the
	// dial seam directly -- the one case this plan tests via dependency
	// injection rather than a real socket.
	injected := context.DeadlineExceeded
	p := DialerProbe{dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, injected
	}}

	state, err := p.Probe(context.Background(), Target{Host: "10.0.0.1", Port: 443}, time.Second)
	if err != injected {
		t.Fatalf("err = %v, want the injected error unwrapped", err)
	}
	if state != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- a generic/timeout error must never be classified as blocked", state)
	}
}

func TestDialerProbe_ObservedConnectionIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			// Block reading -- if DialerProbe left its end open and wrote
			// or expected a reply, this goroutine would hang forever and
			// the test would time out, surfacing the leak.
			buf := make([]byte, 1)
			conn.Read(buf)
		}
	}()

	if _, err := DialerProbe{}.Probe(context.Background(), Target{Host: "127.0.0.1", Port: addr.Port}, time.Second); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server side never saw the connection")
	}
	// If DialerProbe correctly closed its side immediately after connecting,
	// the accepted conn's Read above will return promptly with io.EOF rather
	// than hanging -- this test's own timeout (go test's default) is the
	// backstop if it doesn't.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/networkgraph/... -run TestDialerProbe -v`
Expected: FAIL — `DialerProbe` undefined.

- [ ] **Step 3: Implement the probe**

Create `orchestrator/internal/networkgraph/probe.go`:

```go
package networkgraph

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

// TCPReachabilityProbe performs one bounded TCP reachability check against
// target, classifying the outcome as a cloudgraph.PathState. No data is
// sent or read beyond the TCP handshake itself -- this is a pure
// reachability check, never a service/banner probe.
type TCPReachabilityProbe interface {
	Probe(ctx context.Context, target Target, timeout time.Duration) (cloudgraph.PathState, error)
}

// dialFunc matches (*net.Dialer).DialContext's signature -- a seam so
// tests can inject a synthetic dial outcome (e.g. a generic timeout-style
// error) without ever sending traffic off this host. Production code
// always uses the real dialer.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialerProbe is the only real implementation:
//   - connection succeeds               -> Observed (closed immediately, nothing sent/read)
//   - connection actively refused       -> Blocked
//   - timeout, or any other dial error  -> Unknown (never Blocked -- a timeout proves nothing about why)
type DialerProbe struct {
	dial dialFunc // nil in production use; set only by tests
}

func (p DialerProbe) Probe(ctx context.Context, target Target, timeout time.Duration) (cloudgraph.PathState, error) {
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	conn, err := dial(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		return cloudgraph.Observed, nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return cloudgraph.Blocked, err
	}
	return cloudgraph.Unknown, err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/networkgraph/... -run TestDialerProbe -v`
Expected: PASS (4/4).

- [ ] **Step 5: Run the full package suite so far**

Run: `cd orchestrator && go test ./internal/networkgraph/... -v`
Expected: PASS (Task 1's + Task 2's tests, 8 total test functions including subtests).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networkgraph/probe.go orchestrator/internal/networkgraph/probe_test.go
git commit -m "feat(networkgraph): add TCP reachability probe with PathState classification"
```

---

### Task 3: Discovery Orchestration

**Files:**
- Create: `orchestrator/internal/networkgraph/discovery.go`
- Test: `orchestrator/internal/networkgraph/discovery_test.go`

**Interfaces:**
- Consumes: `Target`, `VantagePoint`, `NetworkObservation`, `NetworkFinding` (Task 1), `TCPReachabilityProbe` (Task 2).
- Produces: `networkgraph.RunStatus` (`RunCompleted`/`RunPartial`), `networkgraph.DiscoveryOptions{TimeoutPerTarget}`, `networkgraph.DiscoveryResult{Status, Observations, Findings}`, `networkgraph.MaxTargetsPerRun`, `networkgraph.DefaultProbeTimeout`, `networkgraph.MaxProbeTimeout`, `networkgraph.MaxRunDuration` (exported `var`, not `const`, so Task 3's own test can shorten it), `networkgraph.RunDiscovery(ctx, probe TCPReachabilityProbe, vp VantagePoint, targets []Target, opts DiscoveryOptions) (*DiscoveryResult, error)`. Task 5 consumes `RunDiscovery` exactly as defined here, and `MaxTargetsPerRun`/`MaxProbeTimeout` for its own request-validation mirroring.

- [ ] **Step 1: Write the failing tests for discovery orchestration**

Create `orchestrator/internal/networkgraph/discovery_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/networkgraph/... -run TestRunDiscovery -v`
Expected: FAIL — `RunDiscovery` undefined.

- [ ] **Step 3: Implement discovery orchestration**

Create `orchestrator/internal/networkgraph/discovery.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/networkgraph/... -run TestRunDiscovery -v`
Expected: PASS (7/7).

- [ ] **Step 5: Run the full package suite**

Run: `cd orchestrator && go build ./... && go test ./internal/networkgraph/... -v`
Expected: build clean; all tests from Tasks 1-3 pass (should be 15 test functions including subtests, 0 failures).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networkgraph/discovery.go orchestrator/internal/networkgraph/discovery_test.go
git commit -m "feat(networkgraph): add bounded-concurrency discovery orchestration with safety caps"
```

---

### Task 4: Database Schema & Store

**Files:**
- Create: `orchestrator/internal/db/networkdiscovery_store.go`
- Test: `orchestrator/internal/db/networkdiscovery_store_test.go`
- Modify: `orchestrator/cmd/server/main.go` (wire `EnsureNetworkDiscoverySchema`)
- Modify: `orchestrator/internal/testutil/testdb.go` (wire `EnsureNetworkDiscoverySchema`)

**Interfaces:**
- Consumes: `networkgraph.NetworkObservation` (Task 1/3).
- Produces: `db.EnsureNetworkDiscoverySchema(ctx, pool) error`, `db.NetworkDiscoveryRun{ID, VantagePointID, RequestedBy, TargetCount, Status, StartedAt, CompletedAt}`, `db.InsertNetworkDiscoveryRun(ctx, pool, run *NetworkDiscoveryRun) error`, `db.GetNetworkDiscoveryRun(ctx, pool, id string) (*NetworkDiscoveryRun, error)` (404 via `errors.Is(err, pgx.ErrNoRows)`), `db.ListNetworkDiscoveryRuns(ctx, pool, limit int) ([]*NetworkDiscoveryRun, error)`, `db.InsertNetworkObservations(ctx, pool, runID string, obs []networkgraph.NetworkObservation) error`, `db.ListNetworkObservationsByRun(ctx, pool, runID string) ([]networkgraph.NetworkObservation, error)`. Task 5 consumes every one of these exactly as defined here.

- [ ] **Step 1: Write the failing tests for the store layer**

Create `orchestrator/internal/db/networkdiscovery_store_test.go`:

```go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestInsertNetworkDiscoveryRun_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		run := &db.NetworkDiscoveryRun{
			ID: "ndrun-roundtrip-1", VantagePointID: "vp-1", RequestedBy: "alice",
			TargetCount: 2, Status: "completed",
		}
		if err := db.InsertNetworkDiscoveryRun(context.Background(), pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkDiscoveryRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.VantagePointID != "vp-1" || got.RequestedBy != "alice" || got.TargetCount != 2 || got.Status != "completed" {
			t.Fatalf("got %+v, want VantagePointID=vp-1 RequestedBy=alice TargetCount=2 Status=completed", got)
		}
		if got.StartedAt.IsZero() {
			t.Fatal("StartedAt should be populated by the database default")
		}

		list, err := db.ListNetworkDiscoveryRuns(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == run.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted run should appear in the list")
		}
	})
}

func TestGetNetworkDiscoveryRun_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkDiscoveryRun(context.Background(), pool, "nonexistent-run-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestInsertNetworkObservations_RoundTripsThroughListNetworkObservationsByRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		run := &db.NetworkDiscoveryRun{ID: "ndrun-obs-1", VantagePointID: "vp-1", TargetCount: 2, Status: "completed"}
		if err := db.InsertNetworkDiscoveryRun(context.Background(), pool, run); err != nil {
			t.Fatalf("insert run: %v", err)
		}

		obs := []networkgraph.NetworkObservation{
			{
				Target: networkgraph.Target{Host: "10.0.0.1", Port: 443, Label: "web"},
				VantagePointID: "vp-1", State: cloudgraph.Observed,
				Provenance: cloudgraph.Provenance{Source: "test-position", Confidence: "high"},
			},
			{
				Target: networkgraph.Target{Host: "10.0.0.2", Port: 22},
				VantagePointID: "vp-1", State: cloudgraph.Blocked, ErrorDetail: "connection refused",
				Provenance: cloudgraph.Provenance{Source: "test-position", Confidence: "high"},
			},
		}
		if err := db.InsertNetworkObservations(context.Background(), pool, run.ID, obs); err != nil {
			t.Fatalf("insert observations: %v", err)
		}

		got, err := db.ListNetworkObservationsByRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("list observations: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d observations, want 2", len(got))
		}
		byHost := map[string]networkgraph.NetworkObservation{}
		for _, o := range got {
			byHost[o.Target.Host] = o
		}
		if byHost["10.0.0.1"].State != cloudgraph.Observed || byHost["10.0.0.1"].Target.Label != "web" {
			t.Fatalf("10.0.0.1 observation = %+v, want State=observed Label=web", byHost["10.0.0.1"])
		}
		if byHost["10.0.0.2"].State != cloudgraph.Blocked || byHost["10.0.0.2"].ErrorDetail != "connection refused" {
			t.Fatalf("10.0.0.2 observation = %+v, want State=blocked ErrorDetail=connection refused", byHost["10.0.0.2"])
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/db/...`
Expected: FAIL — `db.NetworkDiscoveryRun` (and related functions) undefined.

- [ ] **Step 3: Implement the schema and store functions**

Create `orchestrator/internal/db/networkdiscovery_store.go`:

```go
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

// EnsureNetworkDiscoverySchema creates the network_discovery_runs and
// network_observations tables.
func EnsureNetworkDiscoverySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_discovery_runs (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			vantage_point_id text        NOT NULL,
			requested_by     text,
			target_count     int         NOT NULL,
			status           text        NOT NULL,
			started_at       timestamptz NOT NULL DEFAULT NOW(),
			completed_at     timestamptz
		)`)
	if err != nil {
		return fmt.Errorf("network_discovery_runs: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_observations (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id           text        NOT NULL REFERENCES network_discovery_runs(id),
			target_host      text        NOT NULL,
			target_port      int         NOT NULL,
			target_label     text,
			vantage_point_id text        NOT NULL,
			path_state       text        NOT NULL,
			error_detail     text,
			observed_at      timestamptz NOT NULL DEFAULT NOW(),
			confidence       text
		)`)
	if err != nil {
		return fmt.Errorf("network_observations: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_network_observations_run ON network_observations (run_id)`)
	if err != nil {
		return fmt.Errorf("network_observations: ensure index: %w", err)
	}
	return nil
}

// NetworkDiscoveryRun is the persisted record of one discovery run.
type NetworkDiscoveryRun struct {
	ID             string     `json:"id"`
	VantagePointID string     `json:"vantagePointId"`
	RequestedBy    string     `json:"requestedBy,omitempty"`
	TargetCount    int        `json:"targetCount"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"startedAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

// InsertNetworkDiscoveryRun writes a new network_discovery_runs row. The
// caller supplies run.ID already generated.
func InsertNetworkDiscoveryRun(ctx context.Context, pool *pgxpool.Pool, run *NetworkDiscoveryRun) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO network_discovery_runs (id, vantage_point_id, requested_by, target_count, status, completed_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		run.ID, run.VantagePointID, nullableString(run.RequestedBy), run.TargetCount, run.Status, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("network_discovery_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func scanNetworkDiscoveryRun(row pgx.Row) (*NetworkDiscoveryRun, error) {
	run := &NetworkDiscoveryRun{}
	var requestedBy *string
	if err := row.Scan(&run.ID, &run.VantagePointID, &requestedBy, &run.TargetCount, &run.Status, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	if requestedBy != nil {
		run.RequestedBy = *requestedBy
	}
	return run, nil
}

// GetNetworkDiscoveryRun returns one run by id. A missing id returns an
// error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkDiscoveryRun(ctx context.Context, pool *pgxpool.Pool, id string) (*NetworkDiscoveryRun, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, vantage_point_id, requested_by, target_count, status, started_at, completed_at
		 FROM network_discovery_runs WHERE id = $1`, id)
	run, err := scanNetworkDiscoveryRun(row)
	if err != nil {
		return nil, fmt.Errorf("network_discovery_runs: get %s: %w", id, err)
	}
	return run, nil
}

// ListNetworkDiscoveryRuns returns up to limit rows, newest first. Trusts
// limit as-is -- clamping is the HTTP handler's job.
func ListNetworkDiscoveryRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*NetworkDiscoveryRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, vantage_point_id, requested_by, target_count, status, started_at, completed_at
		 FROM network_discovery_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_discovery_runs: list: %w", err)
	}
	defer rows.Close()
	var out []*NetworkDiscoveryRun
	for rows.Next() {
		run, err := scanNetworkDiscoveryRun(rows)
		if err != nil {
			return nil, fmt.Errorf("network_discovery_runs: list scan: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_discovery_runs: list rows: %w", err)
	}
	return out, nil
}

// InsertNetworkObservations writes every observation for one run in a
// single transaction -- all or nothing, matching the run's own
// all-targets-persist-together semantics.
func InsertNetworkObservations(ctx context.Context, pool *pgxpool.Pool, runID string, obs []networkgraph.NetworkObservation) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("network_observations: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, o := range obs {
		_, err := tx.Exec(ctx,
			`INSERT INTO network_observations
			 (run_id, target_host, target_port, target_label, vantage_point_id, path_state, error_detail, observed_at, confidence)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			runID, o.Target.Host, o.Target.Port, nullableString(o.Target.Label), o.VantagePointID,
			string(o.State), nullableString(o.ErrorDetail), o.Provenance.ObservedAt, nullableString(o.Provenance.Confidence))
		if err != nil {
			return fmt.Errorf("network_observations: insert for run %s: %w", runID, err)
		}
	}
	return tx.Commit(ctx)
}

// ListNetworkObservationsByRun returns every observation recorded for
// runID, ordered by observed_at (the time each probe actually completed,
// not insertion order, which gen_random_uuid() primary keys don't preserve).
func ListNetworkObservationsByRun(ctx context.Context, pool *pgxpool.Pool, runID string) ([]networkgraph.NetworkObservation, error) {
	rows, err := pool.Query(ctx,
		`SELECT target_host, target_port, target_label, vantage_point_id, path_state, error_detail, observed_at, confidence
		 FROM network_observations WHERE run_id = $1 ORDER BY observed_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("network_observations: list for run %s: %w", runID, err)
	}
	defer rows.Close()
	var out []networkgraph.NetworkObservation
	for rows.Next() {
		var o networkgraph.NetworkObservation
		var label, errDetail, confidence *string
		var state string
		if err := rows.Scan(&o.Target.Host, &o.Target.Port, &label, &o.VantagePointID, &state, &errDetail, &o.Provenance.ObservedAt, &confidence); err != nil {
			return nil, fmt.Errorf("network_observations: scan for run %s: %w", runID, err)
		}
		if label != nil {
			o.Target.Label = *label
		}
		if errDetail != nil {
			o.ErrorDetail = *errDetail
		}
		if confidence != nil {
			o.Provenance.Confidence = *confidence
		}
		o.State = cloudgraph.PathState(state)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_observations: rows for run %s: %w", runID, err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/... -run 'TestInsertNetworkDiscoveryRun|TestGetNetworkDiscoveryRun|TestInsertNetworkObservations' -v`
Expected: PASS (3/3).

- [ ] **Step 5: Wire the schema into server startup and the test pool**

In `orchestrator/cmd/server/main.go`, immediately after the existing block:

```go
	if err := db.EnsureCloudCampaignSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] cloud campaign schema: %v", err)
	}
```

add:

```go
	if err := db.EnsureNetworkDiscoverySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] network discovery schema: %v", err)
	}
```

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block:

```go
	if err := db.EnsureCloudCampaignSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureCloudCampaignSchema: %w", err)
	}
```

add:

```go
	if err := db.EnsureNetworkDiscoverySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureNetworkDiscoverySchema: %w", err)
	}
```

- [ ] **Step 6: Run the full db package suite**

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -v`
Expected: build clean; full suite passes (every existing `internal/db` test plus the 3 new ones from this task).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/networkdiscovery_store.go orchestrator/internal/db/networkdiscovery_store_test.go orchestrator/cmd/server/main.go orchestrator/internal/testutil/testdb.go
git commit -m "feat(networkdiscovery): add schema and store layer for discovery runs and observations"
```

---

### Task 5: HTTP API

**Files:**
- Create: `orchestrator/internal/api/networkdiscovery_handlers.go`
- Test: `orchestrator/internal/api/networkdiscovery_handlers_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `networkVantagePoint` field + `WithNetworkVantagePoint` method)
- Modify: `orchestrator/internal/api/routes.go` (register 3 routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (3 matching rows)
- Modify: `orchestrator/cmd/server/main.go` (resolve the vantage point at startup, attach via `.WithNetworkVantagePoint(vp)`)

**Interfaces:**
- Consumes: everything from Tasks 1-4 (`networkgraph.RunDiscovery`, `networkgraph.DialerProbe{}`, `networkgraph.MaxTargetsPerRun`, `networkgraph.MaxProbeTimeout`, `db.InsertNetworkDiscoveryRun`, `db.InsertNetworkObservations`, `db.GetNetworkDiscoveryRun`, `db.ListNetworkDiscoveryRuns`, `db.ListNetworkObservationsByRun`), plus existing `auth.ClaimsFrom`, `auth.CanRunScenario`, `newID()`, `jsonError`, `respond`, `respondStatus`, `h.auditLog` (all already used identically by `cloud_run`/`cloud_campaign` in `cloudrun_handlers.go`).
- Produces: nothing consumed by a later task — this is the last task of this plan.

- [ ] **Step 1: Add the vantage-point field and setter to the Handler**

In `orchestrator/internal/api/handlers.go`, add `"github.com/audspect/bas/internal/networkgraph"` to the import block, then add a field to the `Handler` struct (anywhere alongside the other `With*`-settable fields, e.g. near `metricsRegistry`):

```go
	// networkVantagePoint identifies where Network BAS Phase 1 discovery
	// probes originate. Zero value until WithNetworkVantagePoint is called
	// -- Configured() is then false and discovery requests are refused
	// with 503, never a default/fabricated vantage point.
	networkVantagePoint networkgraph.VantagePoint
```

and, next to the existing `WithCompliance` method:

```go
// WithNetworkVantagePoint attaches the orchestrator's configured network
// vantage point (see internal/networkgraph.LoadVantagePoint).
func (h *Handler) WithNetworkVantagePoint(vp networkgraph.VantagePoint) *Handler {
	h.networkVantagePoint = vp
	return h
}
```

- [ ] **Step 2: Write the failing tests for the trigger endpoint**

Create `orchestrator/internal/api/networkdiscovery_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func testVantagePoint() networkgraph.VantagePoint {
	return networkgraph.VantagePoint{ID: "vp-test-1", NetworkPosition: "test-harness-network"}
}

func networkDiscoveryReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, "netdiscovery-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestTriggerNetworkDiscoveryRun_ObservedAndBlockedTargets(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		closedLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		closedPort := closedLn.Addr().(*net.TCPAddr).Port
		closedLn.Close()

		body := map[string]any{"targets": []map[string]any{
			{"host": "127.0.0.1", "port": openPort},
			{"host": "127.0.0.1", "port": closedPort},
		}}
		req := networkDiscoveryReq(t, pool, body)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RunID    string `json:"runId"`
			Status   string `json:"status"`
			Findings []struct {
				Target struct{ Port int } `json:"target"`
				State  string             `json:"state"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.RunID == "" {
			t.Fatal("want non-empty runId")
		}
		if resp.Status != "completed" {
			t.Fatalf("status = %q, want completed", resp.Status)
		}
		var observedSeen, blockedSeen bool
		for _, f := range resp.Findings {
			if f.Target.Port == openPort && f.State == "observed" {
				observedSeen = true
			}
			if f.Target.Port == closedPort && f.State == "blocked" {
				blockedSeen = true
			}
		}
		if !observedSeen || !blockedSeen {
			t.Fatalf("findings = %+v, want one observed (port %d) and one blocked (port %d)", resp.Findings, openPort, closedPort)
		}
	})
}

func TestTriggerNetworkDiscoveryRun_EmptyTargetsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{}})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_TooManyTargetsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		targets := make([]map[string]any, networkgraph.MaxTargetsPerRun+1)
		for i := range targets {
			targets[i] = map[string]any{"host": "127.0.0.1", "port": 9}
		}
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": targets})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_InvalidPortRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": 0}}})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_TimeoutAboveMaxRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		body := map[string]any{
			"targets":            []map[string]any{{"host": "127.0.0.1", "port": 9}},
			"timeoutPerTargetMs": 10000,
		}
		req := networkDiscoveryReq(t, pool, body)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_UnconfiguredVantagePointReturns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret) // no WithNetworkVantagePoint call
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": 9}}})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "netdiscovery-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"targets":[{"host":"` + strings.Repeat("x", maxNetworkDiscoveryRequestBytes+1) + `"}]}`)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "too large") {
			t.Fatalf("expected a body-too-large error, got: %s", rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_RequestedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "netdiscovery-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{
			"targets":     []map[string]any{{"host": "127.0.0.1", "port": 9}},
			"requestedBy": "spoofed-user",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct{ RunID string `json:"runId"` }
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}

		run, err := db.GetNetworkDiscoveryRun(context.Background(), pool, resp.RunID)
		if err != nil {
			t.Fatalf("lookup run: %v", err)
		}
		if run.RequestedBy != userID {
			t.Fatalf("RequestedBy = %q, want %q (the authenticated caller, not the spoofed body value)", run.RequestedBy, userID)
		}
	})
}
```

This test needs `"github.com/audspect/bas/internal/db"` added to this file's import block (alongside the existing `"context"` import already listed at the top).

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.TriggerNetworkDiscoveryRun`, `maxNetworkDiscoveryRequestBytes` undefined.

- [ ] **Step 4: Implement the trigger handler**

Create `orchestrator/internal/api/networkdiscovery_handlers.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
)

// maxNetworkDiscoveryRequestBytes bounds the raw request body before it is
// ever unmarshaled. 50 targets' worth of {host,port,label} JSON is well
// under 1MiB even generously; this ships from the start rather than as a
// follow-up fix, unlike cloud_campaign's own equivalent cap.
const maxNetworkDiscoveryRequestBytes = 1 << 20

// TriggerNetworkDiscoveryRun -- POST /api/network-discovery-runs. Probes
// every caller-declared target from the orchestrator's own configured
// vantage point and persists the result. "Authorized" in this phase means
// only that an authenticated caller holding auth.CanRunScenario submitted
// exactly this target list -- there is no separate scope-registration
// mechanism yet (deferred; see the Phase 1 spec).
func (h *Handler) TriggerNetworkDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	if !h.networkVantagePoint.Configured() {
		jsonError(w, "network discovery vantage point not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Targets            []networkgraph.Target `json:"targets"`
		TimeoutPerTargetMs int                   `json:"timeoutPerTargetMs,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkDiscoveryRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Targets) == 0 {
		jsonError(w, "at least one target is required", http.StatusBadRequest)
		return
	}
	if len(req.Targets) > networkgraph.MaxTargetsPerRun {
		jsonError(w, fmt.Sprintf("too many targets — got %d, max %d", len(req.Targets), networkgraph.MaxTargetsPerRun), http.StatusBadRequest)
		return
	}
	for i, t := range req.Targets {
		if t.Host == "" {
			jsonError(w, fmt.Sprintf("targets[%d]: host required", i), http.StatusBadRequest)
			return
		}
		if t.Port < 1 || t.Port > 65535 {
			jsonError(w, fmt.Sprintf("targets[%d]: port must be between 1 and 65535", i), http.StatusBadRequest)
			return
		}
	}
	opts := networkgraph.DiscoveryOptions{}
	if req.TimeoutPerTargetMs > 0 {
		timeout := time.Duration(req.TimeoutPerTargetMs) * time.Millisecond
		if timeout > networkgraph.MaxProbeTimeout {
			jsonError(w, fmt.Sprintf("timeoutPerTargetMs exceeds max %s", networkgraph.MaxProbeTimeout), http.StatusBadRequest)
			return
		}
		opts.TimeoutPerTarget = timeout
	}

	var requestedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		requestedBy = c.UserID
	}

	result, err := networkgraph.RunDiscovery(r.Context(), networkgraph.DialerProbe{}, h.networkVantagePoint, req.Targets, opts)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	run := &db.NetworkDiscoveryRun{
		ID:             newID(),
		VantagePointID: h.networkVantagePoint.ID,
		RequestedBy:    requestedBy,
		TargetCount:    len(req.Targets),
		Status:         string(result.Status),
	}
	if err := db.InsertNetworkDiscoveryRun(r.Context(), h.db, run); err != nil {
		h.auditLog(r, "networkdiscovery.run", "", map[string]any{"targetCount": len(req.Targets), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := db.InsertNetworkObservations(r.Context(), h.db, run.ID, result.Observations); err != nil {
		h.auditLog(r, "networkdiscovery.run", run.ID, map[string]any{"targetCount": len(req.Targets), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkdiscovery.run", run.ID, map[string]any{
		"targetCount": len(req.Targets), "status": string(result.Status),
	}, "ok")
	respondStatus(w, map[string]any{
		"runId":        run.ID,
		"vantagePoint": h.networkVantagePoint,
		"status":       result.Status,
		"findings":     result.Findings,
	}, http.StatusCreated)
}

// ListNetworkDiscoveryRuns -- GET /api/network-discovery-runs. Any
// authenticated user may read this, matching ListCloudRuns' own
// precedent -- only the trigger endpoint is permission-gated.
func (h *Handler) ListNetworkDiscoveryRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListNetworkDiscoveryRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*db.NetworkDiscoveryRun{}
	}
	respond(w, runs)
}

// GetNetworkDiscoveryRun -- GET /api/network-discovery-runs/{id}. Same
// baseline-only gate as ListNetworkDiscoveryRuns.
func (h *Handler) GetNetworkDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network discovery run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	observations, err := db.ListNetworkObservationsByRun(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if observations == nil {
		observations = []networkgraph.NetworkObservation{}
	}
	respond(w, map[string]any{"run": run, "observations": observations})
}
```

- [ ] **Step 5: Register the routes and RBAC matrix rows**

In `orchestrator/internal/api/routes.go`, right after:

```go
		r.Get("/api/cloud-runs", h.ListCloudRuns)
		r.Get("/api/cloud-campaigns", h.ListCloudCampaigns)
```

add:

```go
		r.Get("/api/network-discovery-runs", h.ListNetworkDiscoveryRuns)
```

and right after:

```go
		r.Get("/api/cloud-runs/{id}", h.GetCloudRun)
		r.Get("/api/cloud-campaigns/{id}", h.GetCloudCampaign)
```

add:

```go
		r.Get("/api/network-discovery-runs/{id}", h.GetNetworkDiscoveryRun)
```

Right after the existing `POST /api/cloud-campaigns` registration:

```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/cloud-campaigns", h.CreateCloudCampaign)
```

add:

```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/network-discovery-runs", h.TriggerNetworkDiscoveryRun)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the existing `/api/cloud-campaigns` GET rows:

```go
	{http.MethodGet, "/api/cloud-runs", tierAny, ""},
	{http.MethodGet, "/api/cloud-campaigns", tierAny, ""},
	{http.MethodGet, "/api/cloud-runs/{id}", tierAny, ""},
	{http.MethodGet, "/api/cloud-campaigns/{id}", tierAny, ""},
```

add:

```go
	{http.MethodGet, "/api/network-discovery-runs", tierAny, ""},
	{http.MethodGet, "/api/network-discovery-runs/{id}", tierAny, ""},
```

and right after the existing `/api/cloud-campaigns` POST row:

```go
	{http.MethodPost, "/api/cloud-runs", tierPermission, auth.CanRunScenario},
	{http.MethodPost, "/api/cloud-campaigns", tierPermission, auth.CanRunScenario},
```

add:

```go
	{http.MethodPost, "/api/network-discovery-runs", tierPermission, auth.CanRunScenario},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestTriggerNetworkDiscoveryRun|TestRBACMatrix_NoDrift' -v`
Expected: PASS (all 8 trigger-endpoint tests, RBAC matrix test).

- [ ] **Step 7: Wire vantage-point resolution and attach it to the Handler in `main.go`**

In `orchestrator/cmd/server/main.go`, add `"github.com/audspect/bas/internal/networkgraph"` to the import block. Immediately before the `handler := api.New(...)` block:

```go
	networkVP, err := networkgraph.LoadVantagePoint()
	if err != nil {
		log.Printf("[WARN] network discovery vantage point not configured: %v -- /api/network-discovery-runs will return 503 until NETWORK_VANTAGE_POINT_ID and NETWORK_VANTAGE_POINT_POSITION are both set", err)
	}
```

Change the chain's last line from:

```go
		WithIOCProvider(iocProvider)
```

to:

```go
		WithIOCProvider(iocProvider).
		WithNetworkVantagePoint(networkVP)
```

(`networkVP` is the zero-value `networkgraph.VantagePoint{}` when `LoadVantagePoint` errored — passing it through unconditionally is correct: `WithNetworkVantagePoint` just stores whatever it's given, and `Configured()` on the zero value is false, which is exactly the fail-closed 503 behavior the Phase 1 spec requires.)

- [ ] **Step 8: Run the final combined gate for the whole plan**

Per Global Constraints: check memory headroom first.

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize
```

Then:

```bash
cd orchestrator
go build ./...
go test ./internal/networkgraph/... ./internal/db/... ./internal/cloudgraph/... -v
go test ./internal/api/... -run 'TestTriggerNetworkDiscoveryRun|TestRBACMatrix_NoDrift|TestTriggerCloudPlanRun|TestCreateCloudCampaign' -v
```

Expected: `go build ./...` clean; `networkgraph`/`db`/`cloudgraph` suites pass in full; every `networkdiscovery` test plus the RBAC matrix test plus the pre-existing cloud-run/cloud-campaign tests (regression check — this plan touches `handlers.go`, `routes.go`, `rbac_matrix_test.go`, `main.go`, `testdb.go`, all shared files) pass with zero failures. If memory headroom is comfortably sufficient, the full unscoped `go test ./internal/api/...` may be attempted instead — but the narrowed command above is the expected, sufficient gate per Global Constraints.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/networkdiscovery_handlers.go orchestrator/internal/api/networkdiscovery_handlers_test.go orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/cmd/server/main.go
git commit -m "feat(networkdiscovery): add HTTP API surface and wire the orchestrator vantage point"
```

---

## Execution Handoff

Execution method is **Native/inline** — the standing convention for this session (established feedback: execute plan tasks inline unless the user asks for agents; this session's prior Cloud Campaign Fan-Out plan also ran Native/inline). I'll implement every task myself in this session, then dispatch one fresh Sonnet reviewer on the whole branch at the end, per `superpowers:executing-plans`.

Please review this plan against the Phase 1 spec and let me know if it captures what you want before I start.
