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
