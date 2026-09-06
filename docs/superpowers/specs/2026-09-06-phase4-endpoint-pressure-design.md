# Phase 4: Endpoint Pressure — Design

**Goal**

Give `sched.ConcurrencyLimiter` (Phase 3, `agent/sched/limiter.go`, shipped `3c8d2fc`) its first
real driver. Today the limiter is wired into `runScenario` at `limit == workers` — a deliberate
no-op, since nothing ever calls `SetLimit`. Phase 4 builds a host-pressure signal (CPU and memory
only — see "Explicitly out of scope") that continuously drives that ceiling down under load and
back up under recovery, so a BAS run backs off automatically on a host that's busy with other work,
instead of adding to the load unconditionally.

**Relationship to Phases 1-3** (all shipped, all on `main`): Phase 1 (`c3c8f4d`) added WS reconnect
backoff. Phase 2 (`39242a3`) added `sched.Recorder` (queue/lock/exec-wait telemetry, timeout/panic
counts) plus a coarse active/queued gauge sampler. Phase 3 (`3c8d2fc`) added the admission-ceiling
mechanism itself. Phase 4 is the first phase whose output is *consumed* by Phase 3's mechanism
rather than adding a new, independently-inert one.

## Context: what exists today, confirmed against real code

**No CPU/memory/disk sampling exists anywhere in the agent.** Grepped every `logger.Metric(...)`
call site across `agent/*.go`: only `heartbeat_latency_ms`, `scenario_duration_ms`,
`ws_reconnect_attempts`, `ws_connection_duration_seconds`, and the 9 `sched_*` metrics from Phase 2
exist. `agent/sysinfo_windows.go` / `sysinfo_linux.go` / `sysinfo_darwin.go` — the file set that
might plausibly already carry this — collect only an OS-version string and (Windows-only)
domain-join status. Nothing in this codebase reads process or system resource usage today.

**The real, working precedent for cross-platform sampling** is `agent/detect_windows.go` /
`detect_linux.go` / `detect_darwin.go` / `detect_other.go`: each implements a package-level function
of the **same name and signature** —
`collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]protocol.AlertRecord, bool)` — gated
by the filename's implicit build tag, called generically from shared code that never branches on
GOOS. Phase 4's sampling functions follow this exact shape.

**`golang.org/x/sys/windows` (already a dependency, v0.45.0) wraps neither `GlobalMemoryStatusEx`
nor `GetSystemTimes`** — verified by grepping the vendored module source directly; neither symbol
appears anywhere in the package. Windows CPU/memory sampling therefore needs hand-rolled raw
syscalls via `windows.NewLazySystemDLL(...).NewProc(...)` — exactly the pattern already used in
`sysinfo_windows.go` for `NetGetJoinInformation` (that function is not wrapped by x/sys either, for
the same reason: it's not one of the ~2000 Win32 APIs x/sys/windows chooses to cover). This is zero
new dependencies, just more code in an already-established style.

**Disk I/O-busy% was investigated and is explicitly out of scope for this phase** (see below) — it
needs the Performance Data Helper API on Windows (a stateful, multi-call API with zero precedent in
this codebase, meaningfully harder than a single syscall) and has no clean answer on macOS at all
without a heavy dependency. The user (this design's stakeholder) confirmed dropping it from Phase 4
rather than substituting disk free-space% (a materially different signal — "is the disk full" vs
"is the disk saturated" — that would create a false impression the disk dimension was implemented)
or accepting a new dependency (gopsutil or similar) purely for this one metric, given the agent's
current dependency list is deliberately minimal (`gorilla/websocket`, `golang.org/x/sys`) and that
minimalism is a real security-posture asset for an endpoint agent (smaller attack surface, simpler
audit, simpler cross-platform behavior).

**`sched.ConcurrencyLimiter` is scenario-run-scoped, not agent-lifetime-scoped**
(`agent/agent.go`, inside `runScenario`: `limiter := sched.NewConcurrencyLimiter(workers)`, a local
variable, created fresh per run and discarded when `sched.Run` returns). A pressure sampler that
runs continuously (see "Lifecycle" below) needs a way to reach whichever limiter is currently live
— exactly the problem `runScenario` already solved once, for pause/resume: `a.pauseGate *sched.Gate`
and `a.pauseEmit func(RunEvent)` are `scenarioMu`-guarded fields on `*Agent`, set when a run starts,
cleared in `runScenario`'s deferred cleanup when it ends, nil-checked by every external caller
(`pauseCurrentScenario`, `resumeCurrentScenario`). Phase 4 adds `a.activeLimiter
*sched.ConcurrencyLimiter` to that same struct, following that same pattern exactly.

## Architecture

```
                    (agent lifetime, started once in main.go)
                              │
                    ┌─────────▼─────────┐
                    │  pressure sampler  │  ticks every 5s
                    │   goroutine        │  (pressureSampleInterval,
                    └─────────┬─────────┘   matches Phase 2's
                              │              gaugeSampleInterval)
                 sampleHost() │ sampleSelf()
              (pressure/sample_<os>.go)
                              │
                    ┌─────────▼─────────┐
                    │ pressure.Controller│  pure logic, no OS calls
                    │   .Observe(cpu,mem)│  EWMA smoothing + 3-state
                    └─────────┬─────────┘  hysteresis (Normal/High/Critical)
                              │
                     Level (Normal/High/Critical)
                              │
                    ┌─────────▼─────────┐
                    │  ceiling ladder    │  Normal → workers
                    │  (package main)    │  High   → max(1, workers/2)
                    └─────────┬─────────┘  Critical→ 1
                              │
                  a.activeLimiter.SetLimit(ceiling)
               (no-op if nil -- no run in progress,
                mirrors a.pauseGate's nil-check exactly)
```

Two new packages/files:

- **`agent/pressure/`** — new package, sibling to `agent/sched/`. Pure, OS-agnostic `Controller`
  logic plus the per-OS `sample_<os>.go` files. No dependency on `package main` or on `sched` — it
  knows nothing about scenarios, jobs, or the limiter. This mirrors `sched`'s own isolation (`sched`
  knows nothing about scenarios either — it only knows jobs and locks).
- **`agent/pressure_loop.go`** (package main) — the glue: owns the ticker, calls `sampleHost`/
  `sampleSelf`, feeds `Controller.Observe`, maps `Level` to a ceiling, calls
  `a.activeLimiter.SetLimit`, and emits telemetry. This mirrors `agent/sched_metrics.go`'s role from
  Phase 2 (pure package logic vs. package-main glue that wires it to the rest of the agent).

## Components

### 1. Sampling (`agent/pressure/sample_windows.go`, `sample_linux.go`, `sample_darwin.go`, `sample_other.go`)

```go
package pressure

// sampleHost returns host-wide CPU and memory utilization as 0-100 percentages.
// err is non-nil on a genuine collection failure (permission denied, a missing
// /proc entry, a failed syscall) OR on the very first call in this process
// (pressure.ErrNoBaseline -- CPU utilization needs a delta between two
// syscalls, and the first call has nothing to diff against). err is never
// used to signal "not supported on this platform" silently as a real-looking
// (0, 0), which would be indistinguishable from "no pressure" and could
// suppress real throttling.
func sampleHost() (cpuPercent, memPercent float64, err error)

// sampleSelf returns this agent process's own CPU and memory utilization,
// same units and error contract as sampleHost. Attribution-only (see
// "Host vs. agent readings" below) -- never fed into Controller.Observe.
func sampleSelf() (cpuPercent, memPercent float64, err error)
```

`sample_other.go` (no `windows`/`linux`/`darwin` build tag — the same fallback role as
`detect_other.go`) returns `(0, 0, errUnsupportedPlatform)` for any other GOOS, so the pressure loop
degrades to "never throttle" rather than failing to build.

CPU utilization on all three platforms is computed as a **delta over two consecutive syscalls**
(idle/busy time deltas, or process CPU-time delta divided by wall-clock delta) — a single snapshot
of cumulative counters is meaningless on its own. `sampleHost`/`sampleSelf` each keep their own
small package-level "previous sample" state (protected by a mutex, since the pressure loop's ticker
is the only caller but the functions should not assume that) to compute this delta internally, so
callers never manage prior-sample state themselves. The very first call on agent startup has no
prior sample to diff against; it returns `(0, 0, pressure.ErrNoBaseline)` for that one call only —
an error, not a real `(0, 0)` reading, specifically so the pressure loop's ordinary
skip-this-tick-on-error handling (see "Lifecycle") takes care of it automatically, and
`Controller.Observe` is guaranteed to never be seeded from a fake zero (see "Controller" below —
this is exactly what makes that section's cold-start seeding rule safe). Every call after the first
establishes a real delta and returns `err == nil`.

### 2. Host vs. agent readings — attribution, not double input

A host-wide CPU/memory reading already includes the agent's own usage; it is the superset signal.
Feeding both `sampleHost` and `sampleSelf` into the same pressure calculation would double-count the
agent's own contribution. Therefore:

- **`sampleHost`'s numbers alone drive `Controller.Observe` and, transitively, the concurrency
  ceiling.** This is the only input the admission decision depends on.
- **`sampleSelf`'s numbers are captured purely for attribution telemetry** — two new metrics,
  `agent_cpu_percent` and `agent_mem_percent` (see "Telemetry" below), reported alongside
  `host_cpu_percent`/`host_mem_percent` so an operator can compare "host busy, agent quiet" against
  "agent itself is the load" after the fact. Confirmed with the design's stakeholder as the intended
  split.

### 3. Controller (`agent/pressure/controller.go`)

```go
package pressure

type Level int

const (
	LevelNormal Level = iota
	LevelHigh
	LevelCritical
)

func (l Level) String() string // "normal" | "high" | "critical" -- for logging/telemetry

// Controller smooths raw host CPU/memory samples via EWMA and classifies the
// result into one of 3 levels with hysteresis, so a single noisy sample can
// never flip the level and the recover threshold is always below the escalate
// threshold (no oscillation). Not safe for concurrent use -- callers serialize
// access themselves (the pressure loop's single ticker goroutine is the only
// caller in this design).
type Controller struct {
	// unexported: ewmaCPU, ewmaMem float64; level Level; initialized bool
}

func NewController() *Controller

// Observe feeds one raw (cpuPercent, memPercent) sample -- both 0-100 -- and
// returns the resulting Level. Pure function of the Controller's internal
// EWMA state: no OS calls, no globals, fully unit-testable with synthetic
// sequences.
func (c *Controller) Observe(cpuPercent, memPercent float64) Level
```

**EWMA smoothing.** `ewma_new = alpha*sample + (1-alpha)*ewma_old`, applied independently to CPU and
memory (never mixed). `alpha = 0.3`, chosen for a ~7-sample (≈35s at the 5s sampling interval)
effective smoothing window — long enough that a single transient spike (a one-off PowerShell cold
start, a momentary GC pause) cannot flip the level, short enough that genuine sustained pressure is
recognized within under a minute. The very first `Observe` call seeds `ewma_old` directly from the
sample (no smoothing to apply yet) rather than starting from 0, which would otherwise read as a
fake initial dip in pressure — safe to do unconditionally because the pressure loop never calls
`Observe` with a cold-start `sampleHost` reading in the first place (that returns
`pressure.ErrNoBaseline` instead of `(0, 0, nil)`, and the loop skips the tick entirely on any
sampling error), so every value `Observe` ever sees, including the first, is a genuine measurement.

**Worst-dimension-wins reduction.** `worst := max(ewmaCPU, ewmaMem)` — never averaged, so a host at
95% memory and 10% CPU is correctly treated as under severe pressure, not diluted to a
misleadingly-moderate 52.5%.

**Hysteresis thresholds** (constants, not configurable in this phase — see "Explicitly out of
scope"):

| Transition | Condition |
|---|---|
| `Normal` → `High` | `worst > 80` |
| `High`/`Normal` → `Critical` | `worst > 90` |
| `High`/`Critical` → `Normal` | `worst < 60` |
| `Critical` → `High` | never directly — critical always recovers straight to Normal once below 60, there is no intermediate "critical relaxing to high" transition, since a separate threshold for that would be a fourth number with no evidence yet that it's needed (YAGNI, matches this project's "Adaptive-but-measure-first" discipline) |

Any `worst` between 60 and 80 holds the current level unchanged (the hysteresis dead zone) — this is
what prevents oscillation: a value oscillating between 65 and 75 never crosses either threshold, so
the level never flaps.

### 4. Ceiling ladder (`agent/pressure_loop.go`, package main)

```go
func ceilingForLevel(level pressure.Level, workers int) int {
	switch level {
	case pressure.LevelHigh:
		c := workers / 2
		if c < 1 { c = 1 }
		return c
	case pressure.LevelCritical:
		return 1
	default: // LevelNormal
		return workers
	}
}
```

### 5. Lifecycle and wiring

- `main.go`: alongside the existing `go agent.connectWS()` / `go agent.startLocalAPI()` /
  `go agent.runSpoolDrainer()` / `go agent.runDisconnectWatchdog()` block, add
  `go agent.runPressureLoop()`. This goroutine runs for the agent's entire lifetime, independent of
  whether a scenario is active — it must be able to observe host pressure that began before any run
  starts.
- `Agent` struct (`agent.go`): add `activeLimiter *sched.ConcurrencyLimiter`, guarded by the
  existing `scenarioMu` (the same mutex that already guards `pauseGate`/`pauseEmit`) — not a new
  mutex, for the same reason `pauseGate` doesn't have its own: all of a run's externally-reachable
  state is one small guarded group.
- `runScenario`: where `limiter := sched.NewConcurrencyLimiter(workers)` is constructed, add
  `a.scenarioMu.Lock(); a.activeLimiter = limiter; a.scenarioMu.Unlock()` right after (mirroring
  exactly how `pauseGate` is set a few lines above it today), and clear it to `nil` in the same
  deferred cleanup block that already clears `pauseGate`/`pauseEmit` when the run ends.
- `runPressureLoop` (in `agent/pressure_loop.go`): a `time.Ticker` at `pressureSampleInterval = 5 *
  time.Second` (matching Phase 2's `gaugeSampleInterval` for consistency, not because the two loops
  share any state). Each tick: call `sampleHost()`/`sampleSelf()`; on a sampling error, log it
  (rate-limited — see "Error handling") and skip the tick entirely, touching neither the
  `Controller` nor the limiter, so a transient sampling failure can never be misread as "zero
  pressure" and never causes a spurious ceiling change; otherwise feed `sampleHost`'s numbers to
  `controller.Observe(...)`, compute the ceiling, and — under `a.scenarioMu` — call
  `a.activeLimiter.SetLimit(ceiling)` if `a.activeLimiter != nil` (no-op otherwise, identical
  nil-check shape to `pauseCurrentScenario`). Emit telemetry every tick regardless of whether a run
  is active (see "Telemetry" — pressure is worth recording even between runs).

### 6. Telemetry

Four new `logger.Metric(...)` call sites, all following Phase 1/2's established naming and unit
conventions:

- `host_cpu_percent` (percent) — raw `sampleHost` CPU reading, not the EWMA (the EWMA is
  Controller-internal state, not separately reported — the level itself, below, is the smoothed
  signal an operator needs)
- `host_mem_percent` (percent)
- `agent_cpu_percent` (percent) — attribution-only, per "Host vs. agent readings"
- `agent_mem_percent` (percent)
- `pressure_level` (count: 0=Normal, 1=High, 2=Critical) — the `Controller`'s classification after
  hysteresis, so the dashboard's Health tab (from the earlier telemetry-visibility work,
  `wwwroot/index.html`'s `_AGT_TELEMETRY_METRICS`/`_AGT_HEALTH_CHARTS`) can add these to its existing
  dropdown groups and curated chart grid as a follow-up — not part of this phase's scope, but the
  metric names are chosen so that follow-up is a small, additive change to those same two arrays,
  the same way Phase 2's metrics were added there previously.

### 7. Error handling

- A `sampleHost`/`sampleSelf` error skips that tick entirely (see "Lifecycle") — never treated as
  `(0, 0)`, which would look identical to "no pressure at all" and could suppress real throttling
  right when the host is in a state where sampling itself is failing (arguably the most dangerous
  time to go silent).
- Sampling errors are logged via `a.logger.Op("warn", "pressure", ...)` but rate-limited to at most
  once per 5 minutes per error type (a simple "last logged at" timestamp per platform-specific error
  path is sufficient — this is not a high-cardinality problem), so a persistent permissions issue on
  a locked-down endpoint doesn't flood the op-log the way an unthrottled per-tick log would.
- `runPressureLoop` itself never panics the agent: any per-tick work is already just arithmetic and
  a mutex-guarded field set, but as a defensive measure consistent with `runJob`'s existing
  panic-recovery contract (`sched/scheduler.go`), the tick body is wrapped in the same
  recover-and-log pattern.

## Explicitly out of scope for this phase

- **Disk I/O-busy%** — deferred to a future phase (informally "4b"), pending real evidence from the
  field that CPU/memory alone are insufficient. Disk free-space% is a different, unrelated signal
  and will not be added as a stand-in.
- **Network, battery/power, and thermal pressure** — no evidence yet that BAS execution is
  meaningfully constrained by any of these; not pursued speculatively (matches this project's
  established "measure before adapting" discipline from Phase 2).
- **Configurable thresholds/ladder** — the 80/90/60 hysteresis bounds and the `workers`/`workers/2`/
  `1` ceiling ladder are fixed constants in this phase. Making them server-configurable policy is a
  reasonable future increment once there's operational experience with the fixed defaults, not
  something to speculatively build now.
- **Per-dimension-weighted pressure** (e.g. treating memory pressure as "worse" than equivalent CPU
  pressure) — worst-dimension-wins already avoids the averaging failure mode; a weighting scheme on
  top of that would be tuning without evidence it's needed.
- **`ResourceProfile`-aware admission** (a CPU-heavy job being denied preferentially over a
  disk-light one under CPU pressure specifically) — this was flagged in the original architecture
  discussion as a later increment ("Phase 5"), building on `sched.ResourceProfile`'s existing
  `Reads`/`Writes`/`Domains` fields. Phase 4's ceiling applies uniformly to all jobs regardless of
  their resource profile.
- **Dashboard visualization of the 5 new metrics** — the metric names are chosen to make this a
  small additive follow-up (see "Telemetry"), but wiring them into `wwwroot/index.html` is not part
  of this phase.

## Testing strategy

- **`pressure.Controller`**: fully unit-testable without any OS dependency — table-driven tests
  feeding synthetic `(cpu, mem)` sequences into `Observe`, asserting the resulting `Level` sequence.
  Required cases: a sustained-high sequence crossing 80 escalates to High; a single transient spike
  above 80 amid otherwise-low samples does *not* escalate (proves EWMA smoothing, not raw-sample
  reaction); crossing 90 escalates to Critical; a value sitting in the 60-80 dead zone after
  escalating holds its current level (proves hysteresis, not the escalate threshold being reused for
  recovery); a memory-only spike with low CPU still escalates (proves worst-wins, not averaging); the
  very first `Observe` call doesn't read as an artificial dip (proves the cold-start seeding rule).
- **`sampleHost`/`sampleSelf`**: thin platform-specific smoke tests (mirroring how this codebase
  already tests other real-OS-state code, e.g. `sysinfo_windows_test.go`) — assert the returned
  percentages are in `[0, 100]` and `err == nil` on the second and subsequent calls on a healthy
  build machine, plus a specific test that the very first call in a fresh process returns
  `pressure.ErrNoBaseline` (the documented cold-start contract — an error, not a real `(0, 0)`
  reading). Not deep unit tests — there is no way to control real host/process resource usage
  deterministically from a test.
- **`runPressureLoop`/`ceilingForLevel`/wiring**: `ceilingForLevel` is pure and gets its own
  table-driven test (`Normal`→`workers`, `High`→`workers/2` floored at 1 for small worker counts,
  `Critical`→`1`). The full loop's integration with `a.activeLimiter` is tested the same way Phase 3
  tested `sched.Run`'s limiter integration — a container-backed or fake-driven test asserting that
  setting the `Controller`'s level (via injected samples) changes `a.activeLimiter.Limit()` when a
  run is active, and does nothing (no panic, no-op) when `a.activeLimiter` is nil.
