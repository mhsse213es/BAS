package observability

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func newTestMetrics(t *testing.T) *MetricsRegistry {
	t.Helper()
	return NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())
}

// clock is a settable time source for the window-based conditions.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func TestActiveStepsAbove(t *testing.T) {
	m := newTestMetrics(t)
	cond := ActiveStepsAbove(m, 50)
	m.ActiveSteps.Set(10)
	if cond() {
		t.Fatal("10 active steps fired a >50 rule")
	}
	m.ActiveSteps.Set(51)
	if !cond() {
		t.Fatal("51 active steps did not fire a >50 rule")
	}
}

func TestExecutionErrorSpike_RatioOverWindow(t *testing.T) {
	m := newTestMetrics(t)
	c := &clock{now: time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)}
	cond := executionErrorSpike(m, 60*time.Second, 0.10, 5, c.Now)

	for i := 0; i < 100; i++ {
		m.ExecutionDuration.WithLabelValues("agent_task").Observe(1)
	}
	if cond() {
		t.Fatal("first evaluation fired with no window yet")
	}

	// 20 completions, 5 errors in the window: 25% > 10%.
	c.now = c.now.Add(60 * time.Second)
	for i := 0; i < 20; i++ {
		m.ExecutionDuration.WithLabelValues("agent_task").Observe(1)
	}
	for i := 0; i < 5; i++ {
		m.ExecutionErrors.WithLabelValues("agent_task", "dispatch_error").Inc()
	}
	if !cond() {
		t.Fatal("25% error ratio over the window did not fire")
	}

	// Next window: 20 completions, 1 error: 5%, recovered.
	c.now = c.now.Add(60 * time.Second)
	for i := 0; i < 20; i++ {
		m.ExecutionDuration.WithLabelValues("agent_task").Observe(1)
	}
	m.ExecutionErrors.WithLabelValues("agent_task", "dispatch_error").Inc()
	if cond() {
		t.Fatal("5% error ratio still fired")
	}
}

func TestExecutionErrorSpike_IgnoresTinySamples(t *testing.T) {
	m := newTestMetrics(t)
	c := &clock{now: time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)}
	cond := executionErrorSpike(m, 60*time.Second, 0.10, 5, c.Now)
	cond()
	c.now = c.now.Add(60 * time.Second)
	// 2 completions, both errors: 100%, but too few to judge.
	m.ExecutionDuration.WithLabelValues("agent_task").Observe(1)
	m.ExecutionDuration.WithLabelValues("agent_task").Observe(1)
	m.ExecutionErrors.WithLabelValues("agent_task", "dispatch_error").Add(2)
	if cond() {
		t.Fatal("two completions fired an error-spike rule")
	}
}

func TestSchedulerStalled_RateBelowHalfExpected(t *testing.T) {
	m := newTestMetrics(t)
	c := &clock{now: time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)}
	// 5s poll interval: 0.2 ticks/s expected; stalled below 0.1/s.
	cond := schedulerStalled(m, 5*time.Second, 60*time.Second, c.Now)
	cond()
	c.now = c.now.Add(60 * time.Second)
	for i := 0; i < 12; i++ { // 0.2/s: healthy
		m.SchedulerTickDuration.Observe(0.001)
	}
	if cond() {
		t.Fatal("healthy tick rate fired the stall rule")
	}
	c.now = c.now.Add(60 * time.Second)
	for i := 0; i < 3; i++ { // 0.05/s: stalled
		m.SchedulerTickDuration.Observe(0.001)
	}
	if !cond() {
		t.Fatal("0.05 ticks/s did not fire the stall rule")
	}
}

func TestSchedulerStalled_NoFireBeforeFullWindow(t *testing.T) {
	m := newTestMetrics(t)
	c := &clock{now: time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)}
	cond := schedulerStalled(m, 5*time.Second, 60*time.Second, c.Now)
	cond()
	c.now = c.now.Add(10 * time.Second) // startup: less than one window
	if cond() {
		t.Fatal("stall rule fired before a full window had passed")
	}
}

func TestPrebuiltRules_ConditionsAreWired(t *testing.T) {
	m := newTestMetrics(t)
	rules := PrebuiltRules(m, 5*time.Second)
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(rules))
	}
	for _, r := range rules {
		if r.Condition == nil || r.Description == "" {
			t.Fatalf("rule %s is incomplete", r.Name)
		}
	}
}
