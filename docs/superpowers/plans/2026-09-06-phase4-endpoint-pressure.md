# Phase 4: Endpoint Pressure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a host CPU/memory pressure signal that continuously drives `sched.ConcurrencyLimiter.SetLimit` (Phase 3's admission ceiling, currently a no-op) so a BAS run backs off under host load and recovers automatically.

**Architecture:** A new pure package `agent/pressure/` (per-OS sampling files + an EWMA/hysteresis `Controller`, no OS-call dependency in the testable core) feeds a thin package-`main` glue file `agent/pressure_loop.go`, which ticks every 5s, updates `a.activeLimiter` (a new `scenarioMu`-guarded field mirroring `a.pauseGate`), and emits 5 new telemetry metrics.

**Tech Stack:** Go 1.26, `golang.org/x/sys/windows` (existing dependency, no new ones added), raw Win32 syscalls via `NewLazySystemDLL` (Windows-only, matching `sysinfo_windows.go`'s existing pattern), `/proc` parsing (Linux), shell-outs to `vm_stat`/`sysctl`/`ps` (macOS, matching `sysinfo_darwin.go`'s existing `sw_vers` shell-out pattern).

**Spec:** `docs/superpowers/specs/2026-09-06-phase4-endpoint-pressure-design.md`

## Global Constraints

- No new Go module dependencies — disk I/O and any dependency-requiring approach are out of scope (spec's "Explicitly out of scope").
- EWMA smoothing constant `alpha = 0.3`.
- Hysteresis thresholds: escalate to High above `80`, escalate to Critical above `90`, recover to Normal only below `60` (all exclusive comparisons: `>`/`<`, never `>=`/`<=`).
- Ceiling ladder: `LevelNormal` → `workers`, `LevelHigh` → `max(1, workers/2)`, `LevelCritical` → `1`.
- Sampling interval: `5 * time.Second`, named `pressureSampleInterval` in `package main` (matches Phase 2's `gaugeSampleInterval`, no shared state between the two).
- Every sampling function returns an explicit error on failure or cold-start — never a real-looking `(0, 0, nil)` for either condition.
- `agent/pressure` package must have zero imports of `package main` or `agent/sched` — it is pure and knows nothing about scenarios or the limiter.
- Host readings alone drive the ceiling; self (agent-process) readings are telemetry-only, never fed into `Controller.Observe`.
- No dashboard changes in this phase (metric names alone make that a small future addition).

---

## File Structure

```
agent/pressure/
  controller.go          # Level, Controller, EWMA + hysteresis -- pure, no OS calls
  controller_test.go
  errors.go               # ErrNoBaseline, shared by all sample_*.go files
  sample_windows.go       # //go:build windows
  sample_windows_test.go  # //go:build windows
  sample_linux.go         # //go:build linux
  sample_linux_test.go    # //go:build linux
  sample_darwin.go        # //go:build darwin
  sample_darwin_test.go   # //go:build darwin
  sample_other.go         # //go:build !windows && !linux && !darwin
  sample_other_test.go    # //go:build !windows && !linux && !darwin

agent/pressure_loop.go       # package main: ceilingForLevel, pressureTick, errorLogGate, (*Agent).runPressureLoop
agent/pressure_loop_test.go

agent/agent.go   # MODIFY: Agent struct (+activeLimiter field), runScenario (set/clear it)
agent/main.go    # MODIFY: launch the pressure loop goroutine
```

Each `sample_<os>.go` implements the same two function signatures (mirrors `detect_windows.go`/`detect_linux.go`/`detect_darwin.go`/`detect_other.go`'s `collectAlerts` convention exactly):

```go
func sampleHost() (cpuPercent, memPercent float64, err error)
func sampleSelf() (cpuPercent, memPercent float64, err error)
```

`errors.go` (no build tag — shared, like `detect_common.go`) holds `var ErrNoBaseline = errors.New("pressure: no baseline sample yet")`, used by every `sample_<os>.go` for its first-call cold-start return.

---

### Task 1: `pressure.Controller` — EWMA smoothing + 3-state hysteresis (pure, TDD)

**Files:**
- Create: `agent/pressure/controller.go`
- Test: `agent/pressure/controller_test.go`

**Interfaces:**
- Produces: `pressure.Level` (`LevelNormal`/`LevelHigh`/`LevelCritical`, with a `String()` method), `pressure.NewController() *Controller`, `(*Controller).Observe(cpuPercent, memPercent float64) Level`. Every later task that needs a `Controller` or `Level` imports these from `agent/pressure`.

- [ ] **Step 1: Write the failing tests**

Create `agent/pressure/controller_test.go`:

```go
package pressure

import "testing"

func TestController_SustainedHighEscalatesToHigh(t *testing.T) {
	c := NewController()
	var lvl Level
	for i := 0; i < 5; i++ {
		lvl = c.Observe(85, 10)
	}
	if lvl != LevelHigh {
		t.Fatalf("after sustained samples at 85%% CPU, level = %v, want %v", lvl, LevelHigh)
	}
}

func TestController_TransientSpikeDoesNotEscalate(t *testing.T) {
	c := NewController()
	for i := 0; i < 5; i++ {
		c.Observe(20, 10) // establish a low, stable baseline
	}
	// One single spike to 95%. EWMA at alpha=0.3 from a baseline of 20 moves
	// to 0.3*95 + 0.7*20 = 42.5 -- nowhere near the 80 escalate threshold.
	lvl := c.Observe(95, 10)
	if lvl != LevelNormal {
		t.Fatalf("after one transient spike, level = %v, want %v (EWMA must absorb a single noisy sample)", lvl, LevelNormal)
	}
}

func TestController_CrossingNinetyEscalatesToCritical(t *testing.T) {
	c := NewController()
	var lvl Level
	for i := 0; i < 5; i++ {
		lvl = c.Observe(95, 10)
	}
	if lvl != LevelCritical {
		t.Fatalf("after sustained samples at 95%% CPU, level = %v, want %v", lvl, LevelCritical)
	}
}

func TestController_DeadZoneHoldsCurrentLevel(t *testing.T) {
	c := NewController()
	for i := 0; i < 5; i++ {
		c.Observe(85, 10) // drive into High; EWMA converges to 85 immediately (constant input)
	}
	// Next sample of 35 moves the EWMA to 0.3*35 + 0.7*85 = 70.0 -- squarely
	// inside the 60-80 dead zone. This must hold High, not revert to Normal
	// just because 70 is below the escalate-high threshold.
	lvl := c.Observe(35, 10)
	if lvl != LevelHigh {
		t.Fatalf("dead-zone sample (EWMA lands at 70%%) changed level to %v, want it to hold %v", lvl, LevelHigh)
	}
}

func TestController_MemoryOnlySpikeEscalatesViaWorstWins(t *testing.T) {
	c := NewController()
	var lvl Level
	// CPU stays low throughout; only memory is high. If dimensions were
	// averaged instead of worst-wins, (10+95)/2 = 52.5 would never escalate.
	for i := 0; i < 5; i++ {
		lvl = c.Observe(10, 95)
	}
	if lvl != LevelCritical {
		t.Fatalf("sustained memory-only pressure: level = %v, want %v (worst-wins must not be diluted by low CPU)", lvl, LevelCritical)
	}
}

func TestController_ColdStartDoesNotFakeADip(t *testing.T) {
	c := NewController()
	// The very first Observe call must seed the EWMA directly from the
	// sample, not from a fake zero baseline. A first sample at 95% must
	// register as Critical immediately, not as diluted/smoothed-from-zero.
	lvl := c.Observe(95, 10)
	if lvl != LevelCritical {
		t.Fatalf("first-ever Observe call at 95%% reported %v, want %v -- cold start is diluting the first real sample as if smoothed from zero", lvl, LevelCritical)
	}
}

func TestController_RecoversToNormalBelowSixty(t *testing.T) {
	c := NewController()
	for i := 0; i < 5; i++ {
		c.Observe(95, 10) // drive into Critical
	}
	var lvl Level
	// Repeated low samples so the EWMA genuinely drops below 60, not just one
	// sample partway there.
	for i := 0; i < 5; i++ {
		lvl = c.Observe(10, 10)
	}
	if lvl != LevelNormal {
		t.Fatalf("after sustained low samples, level = %v, want %v (must recover from Critical straight to Normal)", lvl, LevelNormal)
	}
}

func TestLevel_String(t *testing.T) {
	cases := map[Level]string{LevelNormal: "normal", LevelHigh: "high", LevelCritical: "critical"}
	for level, want := range cases {
		if got := level.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", level, got, want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test ./pressure/... -v`
Expected: FAIL — `package pressure: no Go files` (or `undefined: NewController` once the package exists but is empty).

- [ ] **Step 3: Write the implementation**

Create `agent/pressure/controller.go`:

```go
// Package pressure computes host resource-pressure classification for the
// agent's scheduler admission ceiling (see agent/sched.ConcurrencyLimiter).
// This package is pure and OS-agnostic at its core (Controller); the
// per-OS-file sampling functions (sample_windows.go / sample_linux.go /
// sample_darwin.go / sample_other.go) are the only parts that touch the
// operating system, and they never import anything from package main or
// agent/sched -- this package knows nothing about scenarios, jobs, or the
// limiter, exactly the way agent/sched knows nothing about scenarios either.
package pressure

// Level classifies host pressure after EWMA smoothing and hysteresis.
type Level int

const (
	LevelNormal Level = iota
	LevelHigh
	LevelCritical
)

// String renders the level for logging and telemetry.
func (l Level) String() string {
	switch l {
	case LevelHigh:
		return "high"
	case LevelCritical:
		return "critical"
	default:
		return "normal"
	}
}

const (
	// ewmaAlpha gives a ~7-sample (~35s at the 5s sampling interval)
	// effective smoothing window -- long enough that a single transient
	// spike cannot flip the level, short enough that genuine sustained
	// pressure is recognized within under a minute.
	ewmaAlpha = 0.3

	// Hysteresis thresholds. Recover is strictly below both escalate
	// thresholds so the same value can never simultaneously satisfy an
	// escalate and a recover condition, and the 60-80 gap between
	// escalateHigh and recover is the dead zone that prevents oscillation.
	escalateHighAt     = 80.0
	escalateCriticalAt = 90.0
	recoverAt          = 60.0
)

// Controller smooths raw host CPU/memory samples via EWMA and classifies the
// result into one of 3 levels with hysteresis. Not safe for concurrent use --
// callers serialize access themselves (in this design, the pressure loop's
// single ticker goroutine is the only caller).
type Controller struct {
	ewmaCPU     float64
	ewmaMem     float64
	level       Level
	initialized bool
}

// NewController returns a Controller starting at LevelNormal with no samples
// observed yet.
func NewController() *Controller {
	return &Controller{level: LevelNormal}
}

// Observe feeds one raw (cpuPercent, memPercent) sample -- both expected in
// [0, 100] -- and returns the resulting Level.
func (c *Controller) Observe(cpuPercent, memPercent float64) Level {
	if !c.initialized {
		// Seed directly from the first real sample rather than smoothing
		// from a zero baseline, which would otherwise read as a fake initial
		// dip in pressure. Safe unconditionally: callers must never invoke
		// Observe with a synthetic (0,0) cold-start reading in the first
		// place (see sample_<os>.go's ErrNoBaseline contract) -- every value
		// this method ever sees, including the first, is a genuine
		// measurement.
		c.ewmaCPU = cpuPercent
		c.ewmaMem = memPercent
		c.initialized = true
	} else {
		c.ewmaCPU = ewmaAlpha*cpuPercent + (1-ewmaAlpha)*c.ewmaCPU
		c.ewmaMem = ewmaAlpha*memPercent + (1-ewmaAlpha)*c.ewmaMem
	}

	// Worst-dimension-wins: never averaged, so e.g. 95% memory + 10% CPU is
	// correctly treated as severe pressure, not diluted to a misleading 52.5%.
	worst := c.ewmaCPU
	if c.ewmaMem > worst {
		worst = c.ewmaMem
	}

	switch {
	case worst > escalateCriticalAt:
		c.level = LevelCritical
	case worst > escalateHighAt:
		// Guard: if already Critical, a value that has merely dropped back
		// into (80,90] must NOT step down to High -- recovery from Critical
		// only ever happens via the worst < recoverAt case below. This is
		// what makes "Critical -> High: never directly" true.
		if c.level != LevelCritical {
			c.level = LevelHigh
		}
	case worst < recoverAt:
		c.level = LevelNormal
	}
	// worst in [recoverAt, escalateHighAt] (the dead zone): no case matches,
	// c.level holds unchanged. That IS the hysteresis.

	return c.level
}
```

Create `agent/pressure/errors.go`:

```go
package pressure

import "errors"

// ErrNoBaseline is returned by a sample_<os>.go sampling function on its very
// first call in this process: CPU utilization needs a delta between two
// syscalls (or two /proc reads, or two shell-outs), and the first call has
// nothing to diff against yet. This is an error, never a real-looking
// (0, 0, nil), specifically so callers' ordinary skip-this-tick-on-error
// handling takes care of it automatically -- see agent/pressure_loop.go.
var ErrNoBaseline = errors.New("pressure: no baseline sample yet")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent && go test ./pressure/... -v`
Expected: PASS (all 7 tests).

- [ ] **Step 5: Commit**

```bash
git add agent/pressure/controller.go agent/pressure/controller_test.go agent/pressure/errors.go
git commit -m "feat(agent/pressure): EWMA-smoothed 3-state hysteresis controller

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 2: Windows sampling (`sample_windows.go`)

**Files:**
- Create: `agent/pressure/sample_windows.go`
- Test: `agent/pressure/sample_windows_test.go`

**Interfaces:**
- Consumes: `pressure.ErrNoBaseline` (Task 1).
- Produces: `sampleHost()`, `sampleSelf()` (both `//go:build windows`) -- same signatures as every other `sample_<os>.go`, so Task 6's caller never branches on GOOS.

**Verification note:** this task's test file only *builds* in the cross-platform Docker regression (Task 7) since it is `//go:build windows` and the CI container is Linux -- exactly the same situation as the pre-existing `agent/sysinfo_windows_test.go`. It must be run for real on a Windows machine to execute (not build-verify) it; note this in your task completion rather than treating a Linux-only session as full verification.

- [ ] **Step 1: Write the failing test**

Create `agent/pressure/sample_windows_test.go`:

```go
//go:build windows

package pressure

import "testing"

// TestSampleHost_FirstCallReturnsNoBaseline proves the documented cold-start
// contract: the very first call in a fresh process has nothing to diff CPU
// time against, and must say so via an error rather than a real-looking
// (0, 0, nil).
func TestSampleHost_FirstCallReturnsNoBaseline(t *testing.T) {
	// This package-level state persists across tests in the same process, so
	// this test must run before any other test in this file calls
	// sampleHost. Go runs tests in one file in source order by default and
	// this is the first test in the file, but to be robust against reordering
	// this uses its own dedicated process-level check via a sync.Once-guarded
	// helper is unnecessary here -- if a prior test already consumed the
	// baseline, this test would need resetting, which the package does not
	// expose (by design: sample_<os>.go's prior-sample state is intentionally
	// unexported and untestable-in-isolation, since real hardware is the only
	// thing that can meaningfully validate a delta anyway). Keep this test
	// first in the file and do not add another sampleHost call above it.
	_, _, err := sampleHost()
	if err != ErrNoBaseline {
		t.Fatalf("sampleHost() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

// TestSampleHost_SecondCallReturnsPlausibleReading proves the mechanism
// itself works on a real Windows host: after establishing a baseline, a
// second call (with real elapsed time between the two syscalls) must return
// a real, in-range reading.
func TestSampleHost_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleHost()
	if err != nil {
		t.Fatalf("sampleHost() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleHost() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleHost() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("host: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}

func TestSampleSelf_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleSelf()
	if err != ErrNoBaseline {
		t.Fatalf("sampleSelf() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleSelf_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleSelf()
	if err != nil {
		t.Fatalf("sampleSelf() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleSelf() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleSelf() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("self: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}
```

- [ ] **Step 2: Run test to verify it fails**

This file only builds on Windows. Run (from a Windows machine, or accept build-only verification via Task 7's cross-compile step in the meantime): `cd agent && go test ./pressure/... -v`
Expected: FAIL — `undefined: sampleHost` (the file doesn't exist yet).

- [ ] **Step 3: Write the implementation**

Create `agent/pressure/sample_windows.go`. Verified against the actual vendored `golang.org/x/sys@v0.45.0` source: `windows.GetProcessTimes` and `windows.CurrentProcess()` **are** wrapped (exported, real Go error return); `GetSystemTimes` and `GlobalMemoryStatusEx` are **not** wrapped by x/sys/windows at all (grepped `zsyscall_windows.go` directly — neither symbol appears), so those two need hand-rolled raw syscalls via `NewLazySystemDLL`, exactly the pattern `agent/sysinfo_windows.go` already uses for `NetGetJoinInformation` (also unwrapped, for the same reason). `GetProcessMemoryInfo` (psapi.dll) is likewise unwrapped and needs the same raw-syscall treatment.

```go
//go:build windows

package pressure

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Separate lazy-DLL vars from agent/sysinfo_windows.go's netapi32 ones (that
// file is package main; this is a different package, so there's no actual
// naming collision, but kernel32/psapi are named distinctly here for clarity
// about which API each Proc belongs to.
var (
	pressureKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx      = pressureKernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes            = pressureKernel32.NewProc("GetSystemTimes")
	pressurePsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo      = pressurePsapi.NewProc("GetProcessMemoryInfo")
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX struct (fields in its
// documented order and width). dwLength must be set to sizeof(this struct)
// before the call -- GlobalMemoryStatusEx validates it and fails otherwise.
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// processMemoryCounters mirrors the Win32 PROCESS_MEMORY_COUNTERS struct.
// SIZE_T fields are pointer-width (8 bytes on the amd64 builds this agent
// ships); cb must be set to sizeof(this struct) before the call.
type processMemoryCounters struct {
	cb                         uint32
	_                          uint32 // padding to align the following uintptr fields on amd64
	PageFaultCount             uint32
	_                          uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	hostCPUMu                       sync.Mutex
	hostCPUPrevIdle, hostCPUPrevTot uint64
	hostCPUHasPrev                  bool
)

// sampleHost returns host-wide CPU and memory utilization as 0-100
// percentages. See package pressure's sample_<os>.go doc convention for the
// error contract (genuine failure or ErrNoBaseline on the first call).
func sampleHost() (cpuPercent, memPercent float64, err error) {
	var mem memoryStatusEx
	mem.dwLength = uint32(unsafe.Sizeof(mem))
	ret, _, callErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))
	if ret == 0 {
		return 0, 0, fmt.Errorf("GlobalMemoryStatusEx: %w", callErr)
	}
	// dwMemoryLoad is already "the approximate percentage of physical memory
	// in use", 0-100 -- Windows computes this for us, no division needed.
	memPercent = float64(mem.dwMemoryLoad)

	var idle, kernelT, userT windows.Filetime
	ret, _, callErr = procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernelT)),
		uintptr(unsafe.Pointer(&userT)),
	)
	if ret == 0 {
		return 0, 0, fmt.Errorf("GetSystemTimes: %w", callErr)
	}

	idleTicks := uint64(idle.Nanoseconds())
	// Windows' kernel time accounting INCLUDES idle time, so total busy+idle
	// time is kernel+user, not kernel+user+idle.
	totalTicks := uint64(kernelT.Nanoseconds()) + uint64(userT.Nanoseconds())

	hostCPUMu.Lock()
	defer hostCPUMu.Unlock()
	if !hostCPUHasPrev {
		hostCPUPrevIdle, hostCPUPrevTot = idleTicks, totalTicks
		hostCPUHasPrev = true
		return 0, 0, ErrNoBaseline
	}
	idleDelta := idleTicks - hostCPUPrevIdle
	totalDelta := totalTicks - hostCPUPrevTot
	hostCPUPrevIdle, hostCPUPrevTot = idleTicks, totalTicks

	if totalDelta == 0 {
		cpuPercent = 0
	} else {
		cpuPercent = 100 * (1 - float64(idleDelta)/float64(totalDelta))
	}
	return cpuPercent, memPercent, nil
}

var (
	selfCPUMu        sync.Mutex
	selfCPUPrevTicks uint64
	selfCPUPrevWall  time.Time
	selfCPUHasPrev   bool
)

// sampleSelf returns this agent process's own CPU and memory utilization.
// Attribution-only -- see the design spec's "Host vs. agent readings"; never
// fed into Controller.Observe.
func sampleSelf() (cpuPercent, memPercent float64, err error) {
	// Memory: GetProcessMemoryInfo gives our own working-set size; divide by
	// total physical memory (fetched fresh, independent of sampleHost's own
	// call -- these two functions must not share hidden state) for a percent.
	var mem memoryStatusEx
	mem.dwLength = uint32(unsafe.Sizeof(mem))
	ret, _, callErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))
	if ret == 0 {
		return 0, 0, fmt.Errorf("GlobalMemoryStatusEx: %w", callErr)
	}

	var counters processMemoryCounters
	counters.cb = uint32(unsafe.Sizeof(counters))
	ret, _, callErr = procGetProcessMemoryInfo.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.cb),
	)
	if ret == 0 {
		return 0, 0, fmt.Errorf("GetProcessMemoryInfo: %w", callErr)
	}
	if mem.ullTotalPhys > 0 {
		memPercent = 100 * float64(counters.WorkingSetSize) / float64(mem.ullTotalPhys)
	}

	// CPU: GetProcessTimes IS wrapped by x/sys/windows -- use it directly,
	// no raw syscall needed here.
	var creation, exit, kernelT, userT windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernelT, &userT); err != nil {
		return 0, 0, fmt.Errorf("GetProcessTimes: %w", err)
	}
	ticks := uint64(kernelT.Nanoseconds()) + uint64(userT.Nanoseconds())
	now := time.Now()

	// Wall-clock-normalized: process CPU-time consumed since the last sample,
	// divided by real elapsed wall-clock time (NOT an assumed fixed interval
	// -- this function has no idea how often its caller ticks), converts to a
	// percentage of one core.
	selfCPUMu.Lock()
	defer selfCPUMu.Unlock()
	if !selfCPUHasPrev {
		selfCPUPrevTicks = ticks
		selfCPUPrevWall = now
		selfCPUHasPrev = true
		return 0, 0, ErrNoBaseline
	}
	tickDelta := ticks - selfCPUPrevTicks
	wallDelta := now.Sub(selfCPUPrevWall)
	selfCPUPrevTicks = ticks
	selfCPUPrevWall = now

	if wallDelta <= 0 {
		cpuPercent = 0
	} else {
		cpuPercent = 100 * float64(tickDelta) / float64(wallDelta.Nanoseconds())
	}
	return cpuPercent, memPercent, nil
}
```

(`time` must be added to this file's imports alongside `fmt`/`sync`/`unsafe`/`golang.org/x/sys/windows`.)
This same wall-clock-delta approach is what Task 3's Linux implementation uses for the identical
reason — see that task's `sampleSelf`, which applies it via `/proc/self/stat` instead of
`GetProcessTimes`.

- [ ] **Step 4: Run test to verify it passes** (on a Windows machine; build-only via Docker until then)

Run: `cd agent && go test ./pressure/... -v`
Expected: PASS (all 4 tests), with real logged CPU/mem percentages in `[0,100]`.

- [ ] **Step 5: Commit**

```bash
git add agent/pressure/sample_windows.go agent/pressure/sample_windows_test.go
git commit -m "feat(agent/pressure): Windows host/self CPU+memory sampling

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 3: Linux sampling (`sample_linux.go`)

**Files:**
- Create: `agent/pressure/sample_linux.go`
- Test: `agent/pressure/sample_linux_test.go`

**Interfaces:**
- Consumes: `pressure.ErrNoBaseline` (Task 1).
- Produces: `sampleHost()`, `sampleSelf()` (`//go:build linux`).

This is the one platform whose tests actually **run** (not just build) in this project's standard
Docker verification recipe, since the container itself is Linux.

- [ ] **Step 1: Write the failing test**

Create `agent/pressure/sample_linux_test.go`:

```go
//go:build linux

package pressure

import "testing"

func TestSampleHost_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleHost()
	if err != ErrNoBaseline {
		t.Fatalf("sampleHost() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleHost_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleHost()
	if err != nil {
		t.Fatalf("sampleHost() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleHost() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleHost() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("host: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}

func TestSampleSelf_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleSelf()
	if err != ErrNoBaseline {
		t.Fatalf("sampleSelf() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleSelf_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleSelf()
	if err != nil {
		t.Fatalf("sampleSelf() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleSelf() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleSelf() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("self: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (in the project's standard Docker recipe): `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false golang:1.25-bookworm bash -c 'go test ./pressure/... -v'`
Expected: FAIL — `undefined: sampleHost`.

- [ ] **Step 3: Write the implementation**

Create `agent/pressure/sample_linux.go`:

```go
//go:build linux

package pressure

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// readProcStatCPU reads the first "cpu " line of /proc/stat and returns
// (idleTicks, totalTicks) in kernel jiffies. Format: "cpu  user nice system
// idle iowait irq softirq steal guest guest_nice" (all fields after "cpu" are
// space-separated integers; iowait counts as idle for our purposes, matching
// the standard convention used by tools like `top`).
func readProcStatCPU() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, sc.Err()
	}
	fields := strings.Fields(sc.Text()) // ["cpu", "user", "nice", "system", "idle", "iowait", ...]
	var vals []uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			break // stop at the first non-numeric field; we only need the first 5
		}
		vals = append(vals, v)
	}
	if len(vals) < 4 {
		return 0, 0, errShortProcStat
	}
	user, nice, system, idleField := vals[0], vals[1], vals[2], vals[3]
	iowait := uint64(0)
	if len(vals) > 4 {
		iowait = vals[4]
	}
	idle = idleField + iowait
	total = user + nice + system + idle
	if len(vals) > 5 {
		for _, v := range vals[5:] {
			total += v
		}
	}
	return idle, total, nil
}

// readProcMeminfoPercent reads /proc/meminfo and returns used-memory percent
// as 100*(1 - MemAvailable/MemTotal). MemAvailable (not MemFree) is the
// kernel's own "how much could actually be given to a new process without
// swapping" estimate -- using MemFree alone would overcount page-cache memory
// as "used" when it is in fact readily reclaimable.
func readProcMeminfoPercent() (float64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var total, available uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			available = parseMeminfoKB(line)
		}
	}
	if total == 0 {
		return 0, errShortProcMeminfo
	}
	return 100 * (1 - float64(available)/float64(total)), nil
}

// parseMeminfoKB extracts the numeric kB value from a "Key:   12345 kB" line.
func parseMeminfoKB(line string) uint64 {
	fields := strings.Fields(line) // ["MemTotal:", "12345", "kB"]
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}

var (
	hostCPUMu               sync.Mutex
	hostCPUPrevIdle, hostCPUPrevTot uint64
	hostCPUHasPrev          bool
)

func sampleHost() (cpuPercent, memPercent float64, err error) {
	memPercent, err = readProcMeminfoPercent()
	if err != nil {
		return 0, 0, err
	}

	idle, total, err := readProcStatCPU()
	if err != nil {
		return 0, 0, err
	}

	hostCPUMu.Lock()
	defer hostCPUMu.Unlock()
	if !hostCPUHasPrev {
		hostCPUPrevIdle, hostCPUPrevTot = idle, total
		hostCPUHasPrev = true
		return 0, 0, ErrNoBaseline
	}
	idleDelta := idle - hostCPUPrevIdle
	totalDelta := total - hostCPUPrevTot
	hostCPUPrevIdle, hostCPUPrevTot = idle, total

	if totalDelta == 0 {
		cpuPercent = 0
	} else {
		cpuPercent = 100 * (1 - float64(idleDelta)/float64(totalDelta))
	}
	return cpuPercent, memPercent, nil
}

// readProcSelfStatCPU reads utime+stime (fields 14 and 15, 1-indexed) from
// /proc/self/stat, in clock ticks. The process comm field (field 2) is
// parenthesized and may itself contain spaces or parens, so this splits on
// the LAST ')' rather than naively using strings.Fields on the whole line.
func readProcSelfStatCPU() (ticks uint64, err error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	line := string(data)
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen == -1 || closeParen+2 >= len(line) {
		return 0, errShortProcSelfStat
	}
	rest := strings.Fields(line[closeParen+2:]) // fields from index 3 (state) onward
	// rest[0] = state (field 3), so utime is rest[10] (field 14), stime is rest[11] (field 15).
	if len(rest) < 12 {
		return 0, errShortProcSelfStat
	}
	utime, err1 := strconv.ParseUint(rest[10], 10, 64)
	stime, err2 := strconv.ParseUint(rest[11], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, errShortProcSelfStat
	}
	return utime + stime, nil
}

// readProcSelfVmRSSKB reads VmRSS from /proc/self/status, in KB.
func readProcSelfVmRSSKB() (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			return parseMeminfoKB(line), nil
		}
	}
	return 0, errShortProcSelfStatus
}

const clockTicksPerSec = 100 // USER_HZ -- standard on every mainstream Linux distro this agent targets

var (
	selfCPUMu         sync.Mutex
	selfCPUPrevTicks  uint64
	selfCPUPrevWall   time.Time
	selfCPUHasPrev    bool
)

func sampleSelf() (cpuPercent, memPercent float64, err error) {
	rssKB, err := readProcSelfVmRSSKB()
	if err != nil {
		return 0, 0, err
	}
	totalKB, err := readProcMeminfoTotalKB()
	if err != nil {
		return 0, 0, err
	}
	if totalKB > 0 {
		memPercent = 100 * float64(rssKB) / float64(totalKB)
	}

	ticks, err := readProcSelfStatCPU()
	if err != nil {
		return 0, 0, err
	}
	now := time.Now()

	selfCPUMu.Lock()
	defer selfCPUMu.Unlock()
	if !selfCPUHasPrev {
		selfCPUPrevTicks = ticks
		selfCPUPrevWall = now
		selfCPUHasPrev = true
		return 0, 0, ErrNoBaseline
	}
	tickDelta := ticks - selfCPUPrevTicks
	wallDelta := now.Sub(selfCPUPrevWall)
	selfCPUPrevTicks = ticks
	selfCPUPrevWall = now

	if wallDelta <= 0 {
		cpuPercent = 0
	} else {
		secondsOfCPU := float64(tickDelta) / float64(clockTicksPerSec)
		cpuPercent = 100 * secondsOfCPU / wallDelta.Seconds()
	}
	return cpuPercent, memPercent, nil
}

// readProcMeminfoTotalKB reads just MemTotal from /proc/meminfo, for
// converting sampleSelf's absolute RSS reading into a percentage.
func readProcMeminfoTotalKB() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			return parseMeminfoKB(line), nil
		}
	}
	return 0, errShortProcMeminfo
}
```

Add to `agent/pressure/errors.go` (append, don't replace the existing `ErrNoBaseline`):

```go
var (
	errShortProcStat       = errors.New("pressure: /proc/stat: unexpected format")
	errShortProcMeminfo    = errors.New("pressure: /proc/meminfo: MemTotal not found")
	errShortProcSelfStat   = errors.New("pressure: /proc/self/stat: unexpected format")
	errShortProcSelfStatus = errors.New("pressure: /proc/self/status: VmRSS not found")
)
```

(These are used only by `sample_linux.go`, but living in the shared, untagged `errors.go` is
harmless — Go doesn't complain about unused package-level vars, and it keeps every sentinel error in
one place rather than scattering `errors.New` calls across per-OS files.)

- [ ] **Step 4: Run test to verify it passes**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false golang:1.25-bookworm bash -c 'go test ./pressure/... -v'`
Expected: PASS (all 4 tests), with real logged CPU/mem percentages.

- [ ] **Step 5: Commit**

```bash
git add agent/pressure/sample_linux.go agent/pressure/sample_linux_test.go agent/pressure/errors.go
git commit -m "feat(agent/pressure): Linux host/self CPU+memory sampling via /proc

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 4: macOS sampling (`sample_darwin.go`)

**Files:**
- Create: `agent/pressure/sample_darwin.go`
- Test: `agent/pressure/sample_darwin_test.go`

**Interfaces:**
- Consumes: `pressure.ErrNoBaseline` (Task 1).
- Produces: `sampleHost()`, `sampleSelf()` (`//go:build darwin`).

Same verification caveat as Task 2: this only *builds* (doesn't run) in the Linux Docker regression;
real verification needs a macOS machine, matching this codebase's existing precedent
(`sysinfo_darwin.go` has no `_test.go` at all today, but the shell-out pattern it establishes
`exec.Command("sw_vers", ...)` is exactly what this task follows for `vm_stat`/`sysctl`/`ps`).

- [ ] **Step 1: Write the failing test**

Create `agent/pressure/sample_darwin_test.go`:

```go
//go:build darwin

package pressure

import "testing"

func TestSampleHost_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleHost()
	if err != ErrNoBaseline {
		t.Fatalf("sampleHost() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleHost_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleHost()
	if err != nil {
		t.Fatalf("sampleHost() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleHost() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleHost() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("host: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}

func TestSampleSelf_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleSelf()
	if err != ErrNoBaseline {
		t.Fatalf("sampleSelf() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleSelf_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleSelf()
	if err != nil {
		t.Fatalf("sampleSelf() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleSelf() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleSelf() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("self: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}
```

- [ ] **Step 2: Run test to verify it fails**

On a macOS machine (or accept build-only via Task 7 until then): `cd agent && go test ./pressure/... -v`
Expected: FAIL — `undefined: sampleHost`.

- [ ] **Step 3: Write the implementation**

Create `agent/pressure/sample_darwin.go`. Memory uses `vm_stat` (page counts) + `sysctl -n hw.memsize`
(total bytes) for host, and `ps -o rss=,%cpu= -p <pid>` for self (gives both self-memory in KB and an
OS-computed self-CPU% in one call — no manual delta needed for self on this platform). Host CPU
parses `top -l 1 -n 0`'s "CPU usage:" summary line — a well-established, standard macOS technique
with no cleaner API-level alternative that avoids Cgo or the Mach `host_statistics` API (out of scope
per the design spec's "without adding heavy new dependencies" investigation).

```go
//go:build darwin

package pressure

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// sysctlUint64 shells out to `sysctl -n <name>` and parses the result as a
// uint64. Matches sysinfo_darwin.go's existing exec.Command("sw_vers", ...)
// shell-out precedent -- macOS has no cleaner dependency-free path.
func sysctlUint64(name string) (uint64, error) {
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
}

// vmStatPageSizeAndFree runs `vm_stat` and returns (pageSizeBytes, freePages).
// vm_stat's first line is "Mach Virtual Memory Statistics: (page size of
// 4096 bytes)"; subsequent lines are "Pages free:    12345." (note the
// trailing period, which must be stripped before parsing).
func vmStatPageSizeAndFree() (pageSize uint64, freePages uint64, err error) {
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return 0, 0, errShortVMStat
	}
	// First line: "Mach Virtual Memory Statistics: (page size of 4096 bytes)"
	first := lines[0]
	const marker = "page size of "
	idx := strings.Index(first, marker)
	if idx == -1 {
		return 0, 0, errShortVMStat
	}
	rest := first[idx+len(marker):]
	end := strings.Index(rest, " ")
	if end == -1 {
		return 0, 0, errShortVMStat
	}
	pageSize, err = strconv.ParseUint(rest[:end], 10, 64)
	if err != nil {
		return 0, 0, errShortVMStat
	}

	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "Pages free:") {
			val := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "Pages free:"), "."))
			freePages, err = strconv.ParseUint(val, 10, 64)
			if err != nil {
				return 0, 0, errShortVMStat
			}
			return pageSize, freePages, nil
		}
	}
	return 0, 0, errShortVMStat
}

func hostMemPercent() (float64, error) {
	total, err := sysctlUint64("hw.memsize")
	if err != nil || total == 0 {
		return 0, errShortVMStat
	}
	pageSize, freePages, err := vmStatPageSizeAndFree()
	if err != nil {
		return 0, err
	}
	freeBytes := pageSize * freePages
	return 100 * (1 - float64(freeBytes)/float64(total)), nil
}

// hostCPUPercentFromTop shells out to `top -l 1 -n 0`, which prints one
// sample and no process rows (-n 0), and parses its "CPU usage: 12.34% user,
// 5.67% sys, 81.99% idle" summary line -- this is a single instantaneous
// OS-computed reading (top does its own internal delta), so unlike the
// Windows/Linux host CPU functions, this does NOT need this package's own
// two-call delta/ErrNoBaseline handling for the HOST cpu number specifically.
func hostCPUPercentFromTop() (float64, error) {
	out, err := exec.Command("top", "-l", "1", "-n", "0").Output()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "CPU usage:") {
			continue
		}
		// "CPU usage: 12.34% user, 5.67% sys, 81.99% idle"
		fields := strings.Split(line, ",")
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if strings.HasSuffix(f, "idle") {
				pctStr := strings.TrimSuffix(strings.Fields(f)[0], "%")
				idle, err := strconv.ParseFloat(pctStr, 64)
				if err != nil {
					return 0, errShortTop
				}
				return 100 - idle, nil
			}
		}
	}
	return 0, errShortTop
}

// sampleHost returns host-wide CPU and memory utilization as 0-100
// percentages. Unlike Windows/Linux, `top`'s single-shot summary is already
// delta-computed by the OS, so this never returns ErrNoBaseline for CPU --
// only a genuine command-execution or parse failure produces a non-nil error.
func sampleHost() (cpuPercent, memPercent float64, err error) {
	memPercent, err = hostMemPercent()
	if err != nil {
		return 0, 0, err
	}
	cpuPercent, err = hostCPUPercentFromTop()
	if err != nil {
		return 0, 0, err
	}
	return cpuPercent, memPercent, nil
}

// sampleSelf shells out to `ps -o rss=,%cpu= -p <pid>` for this process,
// which gives both this process's RSS (KB) and an OS-computed %CPU (already
// normalized as "percent of one core" by ps) in a single call -- no manual
// delta or ErrNoBaseline handling needed here either, matching the host
// function's rationale above.
func sampleSelf() (cpuPercent, memPercent float64, err error) {
	pid := os.Getpid()
	out, err := exec.Command("ps", "-o", "rss=,%cpu=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) != 2 {
		return 0, 0, errShortPS
	}
	rssKB, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, errShortPS
	}
	cpuPercent, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, errShortPS
	}

	total, err := sysctlUint64("hw.memsize")
	if err != nil || total == 0 {
		return 0, 0, errShortVMStat
	}
	memPercent = 100 * (rssKB * 1024) / float64(total)
	return cpuPercent, memPercent, nil
}
```

Add to `agent/pressure/errors.go`:

```go
var (
	errShortVMStat = errors.New("pressure: vm_stat/sysctl: unexpected output")
	errShortTop    = errors.New("pressure: top: unexpected output")
	errShortPS     = errors.New("pressure: ps: unexpected output")
)
```

**Important deviation from the other two platforms, call this out explicitly when reporting this
task done:** macOS's `sampleHost`/`sampleSelf` never return `ErrNoBaseline` — `top` and `ps` are
already single-shot, OS-delta-computed readings, unlike the raw cumulative counters Windows/Linux
read directly. The two "FirstCallReturnsNoBaseline" tests in this task's test file will therefore
**fail as written** on real macOS hardware, since there is no cold-start error to return. Delete
those two tests from `sample_darwin_test.go` before running Step 4 on a real Mac, and note in the
commit message why (this is a genuine, spec-consistent platform difference — the design spec's
"error contract" is about not faking a zero reading, and `top -l 1`/`ps` genuinely don't have that
failure mode to report — not a shortcut).

- [ ] **Step 4: Run test to verify it passes** (on a macOS machine; build-only via Docker until then)

First remove `TestSampleHost_FirstCallReturnsNoBaseline` and `TestSampleSelf_FirstCallReturnsNoBaseline`
from `sample_darwin_test.go` per the note above. Then run: `cd agent && go test ./pressure/... -v`
Expected: PASS (the remaining 2 tests), with real logged CPU/mem percentages.

- [ ] **Step 5: Commit**

```bash
git add agent/pressure/sample_darwin.go agent/pressure/sample_darwin_test.go agent/pressure/errors.go
git commit -m "feat(agent/pressure): macOS host/self CPU+memory sampling via vm_stat/top/ps

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 5: Fallback for any other GOOS (`sample_other.go`)

**Files:**
- Create: `agent/pressure/sample_other.go`
- Test: `agent/pressure/sample_other_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks beyond the package itself compiling.
- Produces: `sampleHost()`, `sampleSelf()` (`//go:build !windows && !linux && !darwin`) — mirrors
  `agent/detect_other.go`'s fallback role exactly.

This build tag can never be true on any of this project's 3 shipped GOOS targets, so its test cannot
run in the Linux Docker regression (which builds for `GOOS=linux`) or on real Windows/macOS hardware
either. Verify it only via a cross-compile to a 4th GOOS (e.g. `freebsd`) — build/vet only, never
`go test` (there's no runner for it anywhere in this project's toolchain).

- [ ] **Step 1: Write the test** (cannot be run in this step in any environment available to this
  project — write it anyway, since a written-but-unrunnable-here test still documents the contract
  and will run correctly the one time a `GOOS=freebsd`-class build is ever actually exercised)

Create `agent/pressure/sample_other_test.go`:

```go
//go:build !windows && !linux && !darwin

package pressure

import "testing"

func TestSampleHost_ReturnsUnsupportedPlatform(t *testing.T) {
	cpu, mem, err := sampleHost()
	if err == nil {
		t.Fatal("sampleHost() on an unsupported platform: err = nil, want a non-nil error")
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("sampleHost() = (%v, %v, %v), want (0, 0, err)", cpu, mem, err)
	}
}

func TestSampleSelf_ReturnsUnsupportedPlatform(t *testing.T) {
	cpu, mem, err := sampleSelf()
	if err == nil {
		t.Fatal("sampleSelf() on an unsupported platform: err = nil, want a non-nil error")
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("sampleSelf() = (%v, %v, %v), want (0, 0, err)", cpu, mem, err)
	}
}
```

- [ ] **Step 2: (Skipped — cannot fail-then-pass in an unrunnable environment; proceed to implementation.)**

- [ ] **Step 3: Write the implementation**

Create `agent/pressure/sample_other.go`:

```go
//go:build !windows && !linux && !darwin

package pressure

import "errors"

var errUnsupportedPlatform = errors.New("pressure: host sampling not implemented on this platform")

// sampleHost and sampleSelf on an unrecognized GOOS always fail, so the
// pressure loop degrades to "never throttle" (every tick is skipped, per
// agent/pressure_loop.go's error handling) rather than the agent failing to
// build at all -- mirrors agent/detect_other.go's fallback role exactly.
func sampleHost() (cpuPercent, memPercent float64, err error) {
	return 0, 0, errUnsupportedPlatform
}

func sampleSelf() (cpuPercent, memPercent float64, err error) {
	return 0, 0, errUnsupportedPlatform
}
```

- [ ] **Step 4: Verify via cross-compile (build only, no test execution possible)**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false -e GOOS=freebsd -e GOARCH=amd64 -e CGO_ENABLED=0 golang:1.25-bookworm bash -c 'go vet ./pressure/...'`
Expected: clean (no output, no errors) — proves `sample_other.go` compiles and satisfies the same
signatures as the other 3 platform files under a GOOS none of them apply to.

- [ ] **Step 5: Commit**

```bash
git add agent/pressure/sample_other.go agent/pressure/sample_other_test.go
git commit -m "feat(agent/pressure): fallback sampling for unsupported platforms

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 6: `agent/pressure_loop.go` — ceiling ladder, tick logic, rate-limited errors, and `Agent` wiring

**Files:**
- Create: `agent/pressure_loop.go`
- Test: `agent/pressure_loop_test.go`
- Modify: `agent/agent.go` — add `activeLimiter` field to `Agent` struct; set/clear it in `runScenario`
  (mirroring `pauseGate`/`pauseEmit` exactly); add the `runPressureLoop` method; update the stale
  comment at the `sched.NewConcurrencyLimiter(workers)` call site (it currently says "a future
  pressure controller" — that future is now this task).

**Interfaces:**
- Consumes: `pressure.NewController()`, `pressure.Level`/`LevelNormal`/`LevelHigh`/`LevelCritical`
  (Task 1); `sched.ConcurrencyLimiter` with `SetLimit(int)`/`Limit() int` (already shipped, Phase 3);
  `sampleHost()`/`sampleSelf()` (Tasks 2-5, resolved at build time by GOOS, no import needed — same
  package `pressure`); `a.logger.Metric(name string, value float64, unit string)` and `a.logger.Op(level,
  category, message string)` (existing `*Logger` methods, `agent/logger.go`) — called directly via
  `a.logger`, not through the `metricSink` interface Phase 2 defined in `agent/sched_metrics.go`.
  That interface exists so `runGaugeSampler` (a free function) could be unit-tested without a real
  `*Logger`; `runPressureLoop`/`pressureLoopTick` are methods with direct field access instead, and
  the decision logic worth unit-testing (`ceilingForLevel`, `pressureTick`) never touches logging at
  all, so there is no analogous testability need here — do not redefine or reuse `metricSink` in this
  file.
- Produces: `ceilingForLevel(level pressure.Level, workers int) int`, `pressureTick(ctrl
  *pressure.Controller, limiter *sched.ConcurrencyLimiter, workers int, hostCPU, hostMem float64)
  (level pressure.Level, ceiling int)`, `(*Agent).runPressureLoop()`. Task 7 calls
  `runPressureLoop` from `main.go`; nothing later needs `ceilingForLevel`/`pressureTick` directly
  (they exist for testability, as this task's tests demonstrate).

**Design note carried over from the spec review:** `runPressureLoop` needs to reach `a.activeLimiter`
and `a.logger`, both `*Agent` state — so it is a method, not a free function like Phase 2's
`runGaugeSampler`. But the decision logic itself (`pressureTick`) is factored out as a free function
taking explicit parameters, exactly so it can be unit-tested with a real, cheap
`sched.NewConcurrencyLimiter(...)` and without needing a `*Logger`, goroutines, or a ticker — this is
the same pure-core/thin-shell split every earlier phase in this project already uses (Phase 1's
`wsBackoffDelay`/`wsShouldResetBackoff`, Phase 2's `runMetrics`/`ceilingForLevel`-shaped helpers,
Phase 3's `ConcurrencyLimiter` itself).

- [ ] **Step 1: Write the failing tests**

Create `agent/pressure_loop_test.go`:

```go
package main

import (
	"testing"
	"time"

	"audspect/agent/pressure"
	"audspect/agent/sched"
)

func TestCeilingForLevel(t *testing.T) {
	cases := []struct {
		level   pressure.Level
		workers int
		want    int
	}{
		{pressure.LevelNormal, 8, 8},
		{pressure.LevelHigh, 8, 4},
		{pressure.LevelHigh, 1, 1},   // floored at 1, never 0
		{pressure.LevelHigh, 3, 1},   // 3/2 = 1 (integer division), already >= 1
		{pressure.LevelCritical, 8, 1},
		{pressure.LevelCritical, 1, 1},
	}
	for _, c := range cases {
		if got := ceilingForLevel(c.level, c.workers); got != c.want {
			t.Errorf("ceilingForLevel(%v, %d) = %d, want %d", c.level, c.workers, got, c.want)
		}
	}
}

// TestPressureTick_UpdatesLimiterWhenPresent proves the full decision path:
// feeding a sustained-high sample into a Controller through pressureTick
// actually changes a real ConcurrencyLimiter's ceiling.
func TestPressureTick_UpdatesLimiterWhenPresent(t *testing.T) {
	ctrl := pressure.NewController()
	limiter := sched.NewConcurrencyLimiter(8)

	var level pressure.Level
	var ceiling int
	for i := 0; i < 5; i++ {
		level, ceiling = pressureTick(ctrl, limiter, 8, 95, 10)
	}

	if level != pressure.LevelCritical {
		t.Fatalf("level = %v, want %v after sustained 95%% CPU", level, pressure.LevelCritical)
	}
	if ceiling != 1 {
		t.Fatalf("ceiling = %d, want 1 for Critical", ceiling)
	}
	if got := limiter.Limit(); got != 1 {
		t.Fatalf("limiter.Limit() = %d, want 1 -- pressureTick must call SetLimit on the real limiter", got)
	}
}

// TestPressureTick_NilLimiterIsSafe proves the no-run-in-progress case never
// panics -- pressureTick must be callable with limiter == nil (e.g. the
// pressure loop ticks continuously even when no scenario is active).
func TestPressureTick_NilLimiterIsSafe(t *testing.T) {
	ctrl := pressure.NewController()
	level, ceiling := pressureTick(ctrl, nil, 8, 95, 10)
	if level != pressure.LevelCritical {
		t.Errorf("level = %v, want %v", level, pressure.LevelCritical)
	}
	if ceiling != 1 {
		t.Errorf("ceiling = %d, want 1", ceiling)
	}
	// No assertion beyond "did not panic" -- reaching this line already proves it.
}

// TestErrorLogGate_RateLimitsRepeatedErrors proves the same error key is
// suppressed within the rate-limit window and allowed again after it.
func TestErrorLogGate_RateLimitsRepeatedErrors(t *testing.T) {
	g := newErrorLogGate()
	base := fixedTestTime()

	if !g.shouldLog("host", base) {
		t.Error("first call for a fresh key should log")
	}
	if g.shouldLog("host", base.Add(1*time.Minute)) {
		t.Error("second call within the rate-limit window should NOT log")
	}
	if !g.shouldLog("host", base.Add(6*time.Minute)) {
		t.Error("call after the rate-limit window should log again")
	}
	// A different key is tracked independently.
	if !g.shouldLog("self", base.Add(1*time.Minute)) {
		t.Error("a different error key must not be suppressed by another key's rate limit")
	}
}
```

Add this small test-only helper at the bottom of `agent/pressure_loop_test.go` (keeps the test above
independent of wall-clock time, matching this codebase's existing style of injecting explicit `now`
values into rate-limit/timeout tests rather than sleeping):

```go
func fixedTestTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test . -run "TestCeilingForLevel|TestPressureTick|TestErrorLogGate" -v`
Expected: FAIL — `undefined: ceilingForLevel` (the file doesn't exist yet).

- [ ] **Step 3: Write the implementation**

Create `agent/pressure_loop.go`:

```go
package main

import (
	"log"
	"sync"
	"time"

	"audspect/agent/pressure"
	"audspect/agent/sched"
)

// pressureSampleInterval matches Phase 2's gaugeSampleInterval for
// consistency (no shared state between the two loops -- this is purely a
// tuning-parity choice, not a dependency).
const pressureSampleInterval = 5 * time.Second

// ceilingForLevel maps a pressure.Level to a concurrency ceiling. Pure and
// independently testable -- see the design spec's "Ceiling ladder".
func ceilingForLevel(level pressure.Level, workers int) int {
	switch level {
	case pressure.LevelHigh:
		c := workers / 2
		if c < 1 {
			c = 1
		}
		return c
	case pressure.LevelCritical:
		return 1
	default: // pressure.LevelNormal
		return workers
	}
}

// pressureTick performs one sampling-to-decision cycle given an
// already-taken host sample: feeds it to ctrl, computes the resulting
// ceiling, and applies it to limiter if one is active (nil-safe -- a nil
// limiter means no scenario is currently running, and this is a no-op, not
// an error). Separated from runPressureLoop specifically so this decision
// core is unit-testable without a *Logger, goroutines, or a ticker.
func pressureTick(ctrl *pressure.Controller, limiter *sched.ConcurrencyLimiter, workers int, hostCPU, hostMem float64) (level pressure.Level, ceiling int) {
	level = ctrl.Observe(hostCPU, hostMem)
	ceiling = ceilingForLevel(level, workers)
	if limiter != nil {
		limiter.SetLimit(ceiling)
	}
	return level, ceiling
}

// errorLogGate rate-limits repeated sampling-error log lines so a persistent
// permissions issue on a locked-down endpoint can't flood the op-log the way
// an unthrottled per-tick log would. Keyed by an arbitrary caller-chosen
// string (e.g. "host" vs "self") so the two sampling paths' errors are
// tracked independently.
type errorLogGate struct {
	mu         sync.Mutex
	lastLogged map[string]time.Time
}

func newErrorLogGate() *errorLogGate {
	return &errorLogGate{lastLogged: make(map[string]time.Time)}
}

const errorLogGateWindow = 5 * time.Minute

// shouldLog reports whether an error under this key is due to be logged
// again, and records that it was if so.
func (g *errorLogGate) shouldLog(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	last, seen := g.lastLogged[key]
	if seen && now.Sub(last) < errorLogGateWindow {
		return false
	}
	g.lastLogged[key] = now
	return true
}

// runPressureLoop runs for the agent's entire lifetime (started once in
// main.go, independent of whether a scenario is active) so it can observe
// host pressure that began before any run starts. Each tick: sample host and
// self readings; on a sampling error, log it (rate-limited) and skip the
// tick entirely, touching neither the Controller nor the limiter, so a
// transient sampling failure can never be misread as "zero pressure" and
// never causes a spurious ceiling change. Otherwise feed the host reading to
// pressureTick and emit all 5 telemetry metrics regardless of whether a run
// is active.
func (a *Agent) runPressureLoop() {
	ctrl := pressure.NewController()
	gate := newErrorLogGate()
	t := time.NewTicker(pressureSampleInterval)
	defer t.Stop()

	for range t.C {
		a.pressureLoopTick(ctrl, gate)
	}
}

// pressureLoopTick is one iteration of runPressureLoop's ticker body,
// factored out so a panic in it (arithmetic or field access -- there is no
// I/O in this half, sampling already happened by the time this is called)
// can never take down the agent, matching runJob's existing
// panic-recovery contract (agent/sched/scheduler.go).
//
// workers is read from a.activeWorkers (set by runScenario alongside
// a.activeLimiter -- see the agent.go changes below) rather than calling
// sched.DefaultWorkers() directly, so the ceiling ladder scales relative to
// whatever worker count the actual in-flight run is using, not a
// freshly-recomputed default that might differ from it (a run's Workers can
// be overridden per-command via cmd.Workers). When no run is active,
// a.activeWorkers is 0 (its zero value) and this falls back to
// sched.DefaultWorkers() purely as a reference point for logging/telemetry
// consistency while idle -- SetLimit is never called in that branch anyway,
// since limiter is nil.
func (a *Agent) pressureLoopTick(ctrl *pressure.Controller, gate *errorLogGate) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[pressure] recovered panic in tick: %v", p)
		}
	}()

	now := time.Now()

	hostCPU, hostMem, hostErr := sampleHost()
	selfCPU, selfMem, selfErr := sampleSelf()

	if hostErr != nil {
		if gate.shouldLog("host", now) {
			a.logger.Op("warn", "pressure", "host sampling failed: "+hostErr.Error())
		}
		return // never feed a failed/cold-start host sample into the Controller
	}

	a.scenarioMu.Lock()
	limiter := a.activeLimiter
	workers := a.activeWorkers
	a.scenarioMu.Unlock()
	if workers == 0 {
		workers = sched.DefaultWorkers()
	}

	level, _ := pressureTick(ctrl, limiter, workers, hostCPU, hostMem)

	a.logger.Metric("host_cpu_percent", hostCPU, "percent")
	a.logger.Metric("host_mem_percent", hostMem, "percent")
	a.logger.Metric("pressure_level", float64(level), "count")

	if selfErr != nil {
		if gate.shouldLog("self", now) {
			a.logger.Op("warn", "pressure", "self sampling failed: "+selfErr.Error())
		}
		return // host metrics above still get emitted; self is attribution-only
	}
	a.logger.Metric("agent_cpu_percent", selfCPU, "percent")
	a.logger.Metric("agent_mem_percent", selfMem, "percent")
}
```

Now modify `agent/agent.go`. First, the struct (add two fields next to the existing `pauseGate`/`pauseEmit`):

```go
	pauseGate   *sched.Gate
	pauseEmit   func(RunEvent)
	// activeLimiter and activeWorkers belong to whichever run is currently
	// active, exactly like pauseGate/pauseEmit above (nil/0 when idle or
	// between runs) -- Phase 4's pressure loop reads these every tick under
	// scenarioMu to know which limiter to adjust and what its un-throttled
	// ceiling should be.
	activeLimiter  *sched.ConcurrencyLimiter
	activeWorkers  int
```

Then, at the `runScenario` site that sets `pauseGate`/`pauseEmit` (`agent.go`, the block reading
`gate := sched.NewGate(); a.scenarioMu.Lock(); a.pauseGate = gate; ...`), this task does NOT touch that
block — `activeLimiter`/`activeWorkers` are set later in the same function, where the limiter is
actually constructed. Find:

```go
	limiter := sched.NewConcurrencyLimiter(workers)
	sched.Run(ctx, workers, sched.NewLockManager(), jobs, gate,
		sched.WithRecorder(metrics), sched.WithConcurrencyLimiter(limiter))
```

Replace with:

```go
	// Admission ceiling defaults to the worker count -- a no-op until the
	// Phase 4 pressure loop's ticker (agent/pressure_loop.go) observes
	// sustained host pressure and calls SetLimit to lower it.
	limiter := sched.NewConcurrencyLimiter(workers)
	a.scenarioMu.Lock()
	a.activeLimiter = limiter
	a.activeWorkers = workers
	a.scenarioMu.Unlock()

	sched.Run(ctx, workers, sched.NewLockManager(), jobs, gate,
		sched.WithRecorder(metrics), sched.WithConcurrencyLimiter(limiter))
```

And find the existing deferred cleanup that clears `pauseGate`/`pauseEmit`:

```go
	defer func() {
		a.scenarioMu.Lock()
		a.pauseGate = nil
		a.pauseEmit = nil
		a.scenarioMu.Unlock()
	}()
```

Replace with:

```go
	defer func() {
		a.scenarioMu.Lock()
		a.pauseGate = nil
		a.pauseEmit = nil
		a.activeLimiter = nil
		a.activeWorkers = 0
		a.scenarioMu.Unlock()
	}()
```

`pressureLoopTick` above already reads `a.activeWorkers` (set by these two `runScenario` edits) --
no further change needed there.

- [ ] **Step 4: Run tests to verify they pass**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false golang:1.25-bookworm bash -c 'go build ./... && go test . -run "TestCeilingForLevel|TestPressureTick|TestErrorLogGate" -v'`
Expected: PASS (all 5 tests: `TestCeilingForLevel`, `TestPressureTick_UpdatesLimiterWhenPresent`,
`TestPressureTick_NilLimiterIsSafe`, `TestErrorLogGate_RateLimitsRepeatedErrors`, plus the subtests
under the table-driven `TestCeilingForLevel`).

- [ ] **Step 5: Run the full existing agent test suite to confirm no regression**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false golang:1.25-bookworm bash -c 'go test ./... -timeout 5m'`
Expected: `ok` for every package (`audspect/agent`, `audspect/agent/pressure`,
`audspect/agent/protocol`, `audspect/agent/sched`, `audspect/agent/statusclient`) — in particular,
the existing `pause_test.go` tests (which construct `&Agent{pauseGate: ...}` directly) must still pass
unmodified, since the two new fields default to `nil`/`0` and nothing in those tests touches them.

- [ ] **Step 6: Commit**

```bash
git add agent/pressure_loop.go agent/pressure_loop_test.go agent/agent.go
git commit -m "feat(agent): wire pressure loop into scheduler admission ceiling

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 7: `main.go` wiring + full 3-OS regression

**Files:**
- Modify: `agent/main.go` — launch the pressure loop goroutine.

**Interfaces:**
- Consumes: `(*Agent).runPressureLoop()` (Task 6).
- Produces: nothing further — this is the final integration point; the feature is fully wired after
  this task.

- [ ] **Step 1: Add the goroutine launch**

In `agent/main.go`, find:

```go
	go agent.connectWS()
	go agent.startLocalAPI()
	go agent.runSpoolDrainer()
	go agent.runDisconnectWatchdog()
	agent.sendHeartbeat("idle")
```

Replace with:

```go
	go agent.connectWS()
	go agent.startLocalAPI()
	go agent.runSpoolDrainer()
	go agent.runDisconnectWatchdog()
	go agent.runPressureLoop()
	agent.sendHeartbeat("idle")
```

- [ ] **Step 2: Build and vet on Linux**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false golang:1.25-bookworm bash -c 'go build ./... && go vet ./...'`
Expected: clean, no errors.

- [ ] **Step 3: Run the full test suite on Linux (with race detector)**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false -e CGO_ENABLED=1 golang:1.25-bookworm bash -c 'go test ./... -race -timeout 5m'`
Expected: `ok` for every package. (The pre-existing `TestMislabelIsDetectable` in
`agent/sched/equiv_test.go` is a deliberately-racy canary test, unrelated to this phase — if it flags
under `-race`, that is expected and documented in that test's own comment, not a regression to
chase down.)

- [ ] **Step 4: Cross-compile for Windows**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false -e GOOS=windows -e GOARCH=amd64 -e CGO_ENABLED=0 golang:1.25-bookworm bash -c 'go build -o /tmp/agent_win.exe . && echo WINDOWS_OK'`
Expected: `WINDOWS_OK`. This is the step that actually exercises whether `sample_windows.go`'s raw
syscall struct layouts and DLL/proc bindings compile correctly — a real functional check, not just
`go vet` on that file (which Linux's `go vet ./...` in Step 2/3 does NOT reach, since it's
`//go:build windows`-gated and excluded from a Linux `go vet ./...` run entirely).

- [ ] **Step 5: Cross-compile for macOS**

Run: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false -e GOOS=darwin -e GOARCH=amd64 -e CGO_ENABLED=0 golang:1.25-bookworm bash -c 'go build -o /tmp/agent_mac . && echo DARWIN_OK'`
Expected: `DARWIN_OK`.

- [ ] **Step 6: Manually confirm the spec's out-of-scope boundaries weren't accidentally crossed**

Read through the diff (`git diff` against the commit before Task 1) and confirm:
- No new entries in `agent/go.mod`'s `require` block (grep for `gopsutil` or any unfamiliar module —
  there should be none).
- No disk-related sampling code anywhere in `agent/pressure/`.
- No changes to `wwwroot/index.html` (dashboard wiring is explicitly out of scope this phase).

- [ ] **Step 7: Commit**

```bash
git add agent/main.go
git commit -m "feat(agent): launch the pressure loop at agent startup

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

## Final Verification Checklist (before calling Phase 4 done)

- [ ] `agent/pressure` package: `go test ./pressure/...` green on Linux (the only OS this session's
  Docker recipe can execute); Windows/macOS `sample_*.go` files build-verified via cross-compile in
  Task 7, with a note that real hardware execution of those two `_test.go` files is still owed
  whenever a Windows/macOS machine is available (matching how `sysinfo_windows_test.go` already
  works in this codebase today).
- [ ] `ceilingForLevel`, `pressureTick`, `errorLogGate` all have passing unit tests in `package main`.
- [ ] Existing `pause_test.go`, `sched` package tests, and every other pre-existing test still pass
  unmodified — the two new `Agent` fields (`activeLimiter`, `activeWorkers`) must not require any
  existing test to change.
- [ ] All 3 OS cross-compiles succeed (Windows, Linux, macOS).
- [ ] `go vet ./...` clean on Linux.
- [ ] No new `go.mod` dependencies.
- [ ] `git log` shows one commit per task (7 commits, or slightly more if a task's fix-forward note
  — e.g. Task 2's wall-clock-delta correction — was applied as a follow-up commit within that same
  task rather than folded into the original).
