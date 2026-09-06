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
		{pressure.LevelHigh, 1, 1}, // floored at 1, never 0
		{pressure.LevelHigh, 3, 1}, // 3/2 = 1 (integer division), already >= 1
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

func fixedTestTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func TestRiskAllowedForLevel(t *testing.T) {
	cases := []struct {
		level pressure.Level
		risk  string
		want  bool
	}{
		{pressure.LevelNormal, sched.RiskObservation, true},
		{pressure.LevelNormal, sched.RiskModification, true},
		{pressure.LevelNormal, sched.RiskPersistence, true},
		{pressure.LevelNormal, sched.RiskUnknown, true},
		{pressure.LevelHigh, sched.RiskObservation, true},
		{pressure.LevelHigh, sched.RiskModification, false},
		{pressure.LevelHigh, sched.RiskPersistence, false},
		{pressure.LevelHigh, sched.RiskUnknown, false},
		{pressure.LevelCritical, sched.RiskObservation, true},
		{pressure.LevelCritical, sched.RiskModification, false},
		{pressure.LevelCritical, sched.RiskPersistence, false},
		{pressure.LevelCritical, sched.RiskUnknown, false},
	}
	for _, c := range cases {
		if got := riskAllowedForLevel(c.level, c.risk); got != c.want {
			t.Errorf("riskAllowedForLevel(%v, %q) = %v, want %v", c.level, c.risk, got, c.want)
		}
	}
}
