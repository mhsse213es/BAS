package observability

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond for up to 3s; the engine evaluates on a ticker, so the
// tests wait on observable state instead of sleeping a fixed time.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The chain the production server depends on: a metric changes, the engine's
// periodic evaluation sees it, the alert fires; when the metric recovers, the
// alert resolves.
func TestAlertEngine_FiresOnMetricAndResolvesOnRecovery(t *testing.T) {
	m := newTestMetrics(t)
	engine := NewAlertEngine(5 * time.Millisecond)
	defer engine.Stop()
	if err := engine.AddRule(PrebuiltRules(m, 5*time.Second)[0]); err != nil { // high_active_tasks
		t.Fatal(err)
	}

	m.ActiveSteps.Set(10)
	time.Sleep(30 * time.Millisecond)
	if len(engine.GetFiredAlerts()) != 0 {
		t.Fatal("alert fired with 10 active steps")
	}

	m.ActiveSteps.Set(60)
	waitFor(t, "high_active_tasks to fire", func() bool {
		for _, n := range engine.GetFiredAlerts() {
			if n == "high_active_tasks" {
				return true
			}
		}
		return false
	})

	m.ActiveSteps.Set(5)
	waitFor(t, "high_active_tasks to resolve", func() bool {
		h := engine.GetHistory()
		return len(h) >= 2 && !h[len(h)-1].Firing && h[len(h)-1].RuleName == "high_active_tasks"
	})
}

// RunActiveStepsSampler keeps the gauge equal to the store's count, so every
// start, finish, cancel and fail is reflected without patching each path.
func TestActiveStepsSampler_TracksStoreCount(t *testing.T) {
	m := newTestMetrics(t)
	var count atomic.Int64
	count.Store(7)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunActiveStepsSampler(ctx, m, func(context.Context) (int, error) {
		return int(count.Load()), nil
	}, 5*time.Millisecond)

	waitFor(t, "gauge to read 7", func() bool { return testGauge(m) == 7 })
	count.Store(0)
	waitFor(t, "gauge to drop to 0 after finishes", func() bool { return testGauge(m) == 0 })
}
