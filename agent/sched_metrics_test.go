package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMetricSink is a test double for metricSink, capturing every emitted
// metric by name so tests can assert on both presence and value without a
// real Logger (which opens log files and an HTTP client).
type fakeMetricSink struct {
	mu      sync.Mutex
	metrics map[string][]float64
}

func newFakeMetricSink() *fakeMetricSink {
	return &fakeMetricSink{metrics: make(map[string][]float64)}
}

func (f *fakeMetricSink) Metric(name string, value float64, unit string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metrics[name] = append(f.metrics[name], value)
}

func (f *fakeMetricSink) values(name string) []float64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]float64(nil), f.metrics[name]...)
}

func TestRunMetrics_ReportEmitsAveragesAndMaxima(t *testing.T) {
	m := &runMetrics{}
	m.QueueWait(10 * time.Millisecond)
	m.QueueWait(30 * time.Millisecond)
	m.LockWait(5 * time.Millisecond)
	m.ExecutionTime(100 * time.Millisecond)
	m.ExecutionTime(300 * time.Millisecond)
	m.ScheduleTimeout()
	m.JobPanic()
	m.JobPanic()

	sink := newFakeMetricSink()
	m.report(sink, 10)

	if got := sink.values("sched_jobs_total"); len(got) != 1 || got[0] != 10 {
		t.Errorf("sched_jobs_total = %v, want [10]", got)
	}
	if got := sink.values("sched_timeout_count"); len(got) != 1 || got[0] != 1 {
		t.Errorf("sched_timeout_count = %v, want [1]", got)
	}
	if got := sink.values("sched_panic_count"); len(got) != 1 || got[0] != 2 {
		t.Errorf("sched_panic_count = %v, want [2]", got)
	}
	if got := sink.values("sched_queue_wait_avg_ms"); len(got) != 1 || got[0] != 20 {
		t.Errorf("sched_queue_wait_avg_ms = %v, want [20] ((10+30)/2)", got)
	}
	if got := sink.values("sched_queue_wait_max_ms"); len(got) != 1 || got[0] != 30 {
		t.Errorf("sched_queue_wait_max_ms = %v, want [30]", got)
	}
	if got := sink.values("sched_lock_wait_avg_ms"); len(got) != 1 || got[0] != 5 {
		t.Errorf("sched_lock_wait_avg_ms = %v, want [5]", got)
	}
	if got := sink.values("sched_execution_avg_ms"); len(got) != 1 || got[0] != 200 {
		t.Errorf("sched_execution_avg_ms = %v, want [200] ((100+300)/2)", got)
	}
	if got := sink.values("sched_execution_max_ms"); len(got) != 1 || got[0] != 300 {
		t.Errorf("sched_execution_max_ms = %v, want [300]", got)
	}
}

// TestRunMetrics_ReportSkipsAveragesForUnusedDimensions proves a run with no
// schedule timeouts and no lock contention doesn't emit misleading avg/max=0
// metrics for lock wait -- only the dimensions that actually happened.
func TestRunMetrics_ReportSkipsAveragesForUnusedDimensions(t *testing.T) {
	m := &runMetrics{}
	m.ExecutionTime(50 * time.Millisecond)

	sink := newFakeMetricSink()
	m.report(sink, 1)

	for _, name := range []string{"sched_lock_wait_avg_ms", "sched_lock_wait_max_ms", "sched_queue_wait_avg_ms", "sched_queue_wait_max_ms"} {
		if got := sink.values(name); len(got) != 0 {
			t.Errorf("%s = %v, want no emission (no lock/queue waits recorded)", name, got)
		}
	}
	if got := sink.values("sched_execution_avg_ms"); len(got) != 1 || got[0] != 50 {
		t.Errorf("sched_execution_avg_ms = %v, want [50]", got)
	}
}

func TestRunMetrics_Retry_EmitsRetryCount(t *testing.T) {
	m := &runMetrics{}
	m.Retry()
	m.Retry()
	m.Retry()

	sink := newFakeMetricSink()
	m.report(sink, 5)

	if got := sink.values("sched_retry_count"); len(got) != 1 || got[0] != 3 {
		t.Errorf("sched_retry_count = %v, want [3]", got)
	}
}

func TestRunMetrics_Retry_NoCallsEmitsNothing(t *testing.T) {
	m := &runMetrics{}
	m.ExecutionTime(10 * time.Millisecond) // some unrelated activity, no retries

	sink := newFakeMetricSink()
	m.report(sink, 1)

	if got := sink.values("sched_retry_count"); len(got) != 0 {
		t.Errorf("sched_retry_count = %v, want no emission (no retries recorded)", got)
	}
}

func TestRunMetrics_Breaker_EmitsOpenAndSuppressedCounts(t *testing.T) {
	m := &runMetrics{}
	m.BreakerOpened()
	m.BreakerOpened()
	m.BreakerSuppressed()
	m.BreakerSuppressed()
	m.BreakerSuppressed()

	sink := newFakeMetricSink()
	m.report(sink, 5)

	if got := sink.values("sched_breaker_open_count"); len(got) != 1 || got[0] != 2 {
		t.Errorf("sched_breaker_open_count = %v, want [2]", got)
	}
	if got := sink.values("sched_breaker_suppressed_count"); len(got) != 1 || got[0] != 3 {
		t.Errorf("sched_breaker_suppressed_count = %v, want [3]", got)
	}
}

func TestRunMetrics_Breaker_NoCallsEmitsNothing(t *testing.T) {
	m := &runMetrics{}
	m.ExecutionTime(10 * time.Millisecond) // some unrelated activity, no breaker events

	sink := newFakeMetricSink()
	m.report(sink, 1)

	for _, name := range []string{"sched_breaker_open_count", "sched_breaker_suppressed_count"} {
		if got := sink.values(name); len(got) != 0 {
			t.Errorf("%s = %v, want no emission (no breaker events recorded)", name, got)
		}
	}
}

func TestRunGaugeSampler_ReportsActiveAndQueuedThenStopsOnDone(t *testing.T) {
	var started, finished int64
	atomic.StoreInt64(&started, 3)
	atomic.StoreInt64(&finished, 1)

	sink := newFakeMetricSink()
	done := make(chan struct{})

	go runGaugeSampler(sink, &started, &finished, 10, 5*time.Millisecond, done)

	deadline := time.After(2 * time.Second)
	for {
		if len(sink.values("sched_active_jobs")) > 0 && len(sink.values("sched_queued_jobs")) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for at least one gauge sample")
		case <-time.After(time.Millisecond):
		}
	}
	close(done)

	active := sink.values("sched_active_jobs")
	if active[0] != 2 { // started(3) - finished(1)
		t.Errorf("sched_active_jobs = %v, want first sample 2", active)
	}
	queued := sink.values("sched_queued_jobs")
	if queued[0] != 7 { // total(10) - started(3)
		t.Errorf("sched_queued_jobs = %v, want first sample 7", queued)
	}

	// Stopping must actually stop the ticker: no new samples should land
	// after a brief pause once done is closed.
	nBefore := len(sink.values("sched_active_jobs"))
	time.Sleep(30 * time.Millisecond)
	if nAfter := len(sink.values("sched_active_jobs")); nAfter != nBefore {
		t.Errorf("sampler kept emitting after done was closed: %d -> %d samples", nBefore, nAfter)
	}
}

func TestRunMetrics_AdmissionWait_EmitsAllowedAndDeferredCounts(t *testing.T) {
	m := &runMetrics{}
	// 3 near-instant admissions (never deferred) + 2 genuinely deferred ones.
	m.AdmissionWait(1 * time.Millisecond)
	m.AdmissionWait(2 * time.Millisecond)
	m.AdmissionWait(0)
	m.AdmissionWait(50 * time.Millisecond)
	m.AdmissionWait(150 * time.Millisecond)

	sink := newFakeMetricSink()
	m.report(sink, 5)

	if got := sink.values("sched_admission_allowed_count"); len(got) != 1 || got[0] != 5 {
		t.Errorf("sched_admission_allowed_count = %v, want [5] (every AdmissionWait call counts)", got)
	}
	if got := sink.values("sched_admission_deferred_count"); len(got) != 1 || got[0] != 2 {
		t.Errorf("sched_admission_deferred_count = %v, want [2] (only calls above admissionDeferThreshold)", got)
	}
	if got := sink.values("sched_admission_defer_wait_avg_ms"); len(got) != 1 || got[0] != 100 {
		t.Errorf("sched_admission_defer_wait_avg_ms = %v, want [100] ((50+150)/2, excluding the 3 non-deferred)", got)
	}
	if got := sink.values("sched_admission_defer_wait_max_ms"); len(got) != 1 || got[0] != 150 {
		t.Errorf("sched_admission_defer_wait_max_ms = %v, want [150]", got)
	}
}

// TestRunMetrics_AdmissionWait_NoCallsEmitsNothing proves a run with no
// RiskGate configured (AdmissionWait never called) doesn't emit misleading
// zero-value admission metrics -- same "only emit dimensions that happened"
// convention as the existing lock/queue-wait tests.
func TestRunMetrics_AdmissionWait_NoCallsEmitsNothing(t *testing.T) {
	m := &runMetrics{}
	m.ExecutionTime(10 * time.Millisecond) // some other dimension did happen

	sink := newFakeMetricSink()
	m.report(sink, 1)

	for _, name := range []string{"sched_admission_allowed_count", "sched_admission_deferred_count", "sched_admission_defer_wait_avg_ms", "sched_admission_defer_wait_max_ms"} {
		if got := sink.values(name); len(got) != 0 {
			t.Errorf("%s = %v, want no emission (AdmissionWait never called)", name, got)
		}
	}
}
