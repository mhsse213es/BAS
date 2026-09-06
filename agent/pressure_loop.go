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

// riskAllowedForLevel decides whether a job of this risk classification may
// be admitted under the given pressure level. Pure and independently
// testable -- mirrors ceilingForLevel's shape exactly. Normal admits
// everything; High and Critical both defer anything that isn't
// RiskObservation (RiskUnknown included, per effectiveRisk's conservative
// default) -- collapsed to one policy for both non-Normal levels rather than
// giving Critical its own stricter rule, since Phase 4's ceiling (workers/2
// vs 1) already differentiates the two levels along a separate axis, and
// there is no evidence yet that High's risk policy is insufficient at
// Critical.
func riskAllowedForLevel(level pressure.Level, risk string) bool {
	if level == pressure.LevelNormal {
		return true
	}
	return risk == sched.RiskObservation
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
// host pressure that began before any run starts.
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
// a.activeLimiter) rather than calling sched.DefaultWorkers() directly, so
// the ceiling ladder scales relative to whatever worker count the actual
// in-flight run is using, not a freshly-recomputed default that might differ
// from it (a run's Workers can be overridden per-command via cmd.Workers).
// When no run is active, a.activeWorkers is 0 (its zero value) and this
// falls back to sched.DefaultWorkers() purely as a reference point for
// logging/telemetry consistency while idle -- SetLimit is never called in
// that branch anyway, since limiter is nil.
func (a *Agent) pressureLoopTick(ctrl *pressure.Controller, gate *errorLogGate) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[pressure] recovered panic in tick: %v", p)
		}
	}()

	now := time.Now()

	hostCPU, hostMem, hostErr := pressure.SampleHost()
	selfCPU, selfMem, selfErr := pressure.SampleSelf()

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
