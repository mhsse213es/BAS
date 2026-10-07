package observability

import (
	"context"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// Conditions read the metrics registry, so the rules fire on what the
// executor and scheduler actually record. Windowed conditions keep their own
// samples: each evaluation appends one and compares against the sample at
// least one window earlier.

// familySum returns the sum over every series of a metric. Counters and
// gauges sum their values; histograms sum their observation counts.
func familySum(m *MetricsRegistry, name string) float64 {
	raw, err := m.Gather()
	if err != nil || raw == nil {
		return 0
	}
	families, ok := raw.([]*dto.MetricFamily)
	if !ok {
		return 0
	}
	var total float64
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, metric := range f.GetMetric() {
			switch {
			case metric.GetCounter() != nil:
				total += metric.GetCounter().GetValue()
			case metric.GetGauge() != nil:
				total += metric.GetGauge().GetValue()
			case metric.GetHistogram() != nil:
				total += float64(metric.GetHistogram().GetSampleCount())
			}
		}
	}
	return total
}

// ActiveStepsAbove fires when more than threshold exercise steps are active.
func ActiveStepsAbove(m *MetricsRegistry, threshold float64) func() bool {
	return func() bool {
		return m.ActiveSteps != nil && testGauge(m) > threshold
	}
}

func testGauge(m *MetricsRegistry) float64 {
	return familySum(m, "exercise_active_steps")
}

type sample struct {
	at   time.Time
	a, b float64
}

// trailing keeps samples for a sliding window and returns the one at or
// before now-window, which is the start of the comparison.
type trailing struct {
	window  time.Duration
	samples []sample
}

func (t *trailing) add(now time.Time, a, b float64) (start sample, ok bool) {
	t.samples = append(t.samples, sample{at: now, a: a, b: b})
	cutoff := now.Add(-t.window)
	// Keep the newest sample at or before the cutoff; drop anything older.
	keep := 0
	for i, s := range t.samples {
		if !s.at.After(cutoff) {
			keep = i
		}
	}
	t.samples = t.samples[keep:]
	if len(t.samples) < 2 || t.samples[0].at.After(cutoff) {
		return sample{}, false
	}
	return t.samples[0], true
}

// executionErrorSpike fires when dispatch errors exceed ratio of completed
// executions over the window. Fewer than minCompletions completions in the
// window is too little to judge, so it does not fire.
func executionErrorSpike(m *MetricsRegistry, window time.Duration, ratio float64, minCompletions float64, now func() time.Time) func() bool {
	tr := &trailing{window: window}
	return func() bool {
		cur := now()
		start, ok := tr.add(cur, familySum(m, "execution_errors_total"), familySum(m, "execution_duration_seconds"))
		if !ok {
			return false
		}
		errs := familySum(m, "execution_errors_total") - start.a
		completions := familySum(m, "execution_duration_seconds") - start.b
		if completions < minCompletions {
			return false
		}
		return errs/completions > ratio
	}
}

// ExecutionErrorSpike is the rule the engine uses: more than 10% of
// completions in the last 60s failed, with at least 5 completions to judge.
func ExecutionErrorSpike(m *MetricsRegistry) func() bool {
	return executionErrorSpike(m, 60*time.Second, 0.10, 5, time.Now)
}

// schedulerStalled fires when the scheduler tick rate over the window falls
// below half the rate its own interval implies. The threshold has to come
// from the interval: a 5s poll gives 0.2 ticks/s even when healthy.
func schedulerStalled(m *MetricsRegistry, interval, window time.Duration, now func() time.Time) func() bool {
	expected := 1 / interval.Seconds()
	tr := &trailing{window: window}
	return func() bool {
		cur := now()
		start, ok := tr.add(cur, familySum(m, "scheduler_tick_duration_seconds"), 0)
		if !ok {
			return false
		}
		elapsed := cur.Sub(start.at).Seconds()
		if elapsed <= 0 {
			return false
		}
		rate := (familySum(m, "scheduler_tick_duration_seconds") - start.a) / elapsed
		return rate < expected/2
	}
}

// SchedulerStalled is the rule for the exercise scheduler polled every interval.
func SchedulerStalled(m *MetricsRegistry, interval time.Duration) func() bool {
	return schedulerStalled(m, interval, 60*time.Second, time.Now)
}

// RunActiveStepsSampler sets m.ActiveSteps from count every interval until
// ctx is done. A failed count keeps the last value rather than reporting zero.
func RunActiveStepsSampler(ctx context.Context, m *MetricsRegistry, count func(context.Context) (int, error), every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := count(ctx); err == nil {
				m.ActiveSteps.Set(float64(n))
			}
		}
	}
}
