package main

import (
	"sync"
	"sync/atomic"
	"time"

	"audspect/agent/sched"
)

// runMetrics implements sched.Recorder for one scenario run, aggregating
// per-job durations in memory and reporting a single summary once the run
// completes -- never one event per step. A Full Sweep run can dispatch tens
// of thousands of steps (see fullsweep.PNG-driven fix), and the agent
// Logger's buffer (logBufferCap=500, see logger.go) would silently drop
// almost all of a per-step telemetry stream long before it ever reached the
// server. This is Phase 2 of the scheduler-observability work: pure
// measurement, no admission/throttling decision reads it yet.
type runMetrics struct {
	mu sync.Mutex

	queueWaitTotal time.Duration
	queueWaitMax   time.Duration
	queueWaitN     int64

	lockWaitTotal time.Duration
	lockWaitMax   time.Duration
	lockWaitN     int64

	execTotal time.Duration
	execMax   time.Duration
	execN     int64

	scheduleTimeouts int64
	jobPanics        int64

	admissionWaitTotal time.Duration
	admissionWaitMax   time.Duration
	admissionWaitN     int64

	admissionDeferTotal time.Duration
	admissionDeferMax   time.Duration
	admissionDeferN     int64
}

// admissionDeferThreshold: an AdmissionWait below this is "admitted
// instantly" (the RiskGate's policy already allowed it) rather than
// genuinely deferred -- named, not a bare magic number, matching this
// codebase's established style (see defaultGraceSec/waitDelaySlackSec in
// agent/executor.go).
const admissionDeferThreshold = 10 * time.Millisecond

var _ sched.Recorder = (*runMetrics)(nil)

// metricSink is the one Logger method this file depends on, narrowed to keep
// report/runGaugeSampler testable without a real Logger (which opens log
// files and an HTTP client). *Logger satisfies this today with no changes.
type metricSink interface {
	Metric(name string, value float64, unit string)
}

func (m *runMetrics) QueueWait(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueWaitTotal += d
	if d > m.queueWaitMax {
		m.queueWaitMax = d
	}
	m.queueWaitN++
}

func (m *runMetrics) LockWait(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockWaitTotal += d
	if d > m.lockWaitMax {
		m.lockWaitMax = d
	}
	m.lockWaitN++
}

func (m *runMetrics) ExecutionTime(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.execTotal += d
	if d > m.execMax {
		m.execMax = d
	}
	m.execN++
}

func (m *runMetrics) ScheduleTimeout() {
	atomic.AddInt64(&m.scheduleTimeouts, 1)
}

func (m *runMetrics) JobPanic() {
	atomic.AddInt64(&m.jobPanics, 1)
}

func (m *runMetrics) AdmissionWait(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.admissionWaitTotal += d
	if d > m.admissionWaitMax {
		m.admissionWaitMax = d
	}
	m.admissionWaitN++
	if d >= admissionDeferThreshold {
		m.admissionDeferTotal += d
		if d > m.admissionDeferMax {
			m.admissionDeferMax = d
		}
		m.admissionDeferN++
	}
}

// report emits one summary Metric per dimension. Called once, after
// sched.Run returns.
func (m *runMetrics) report(logger metricSink, total int) {
	m.mu.Lock()
	queueTotal, queueMax, queueN := m.queueWaitTotal, m.queueWaitMax, m.queueWaitN
	lockTotal, lockMax, lockN := m.lockWaitTotal, m.lockWaitMax, m.lockWaitN
	execTotal, execMax, execN := m.execTotal, m.execMax, m.execN
	admissionN := m.admissionWaitN
	deferTotal, deferMax, deferN := m.admissionDeferTotal, m.admissionDeferMax, m.admissionDeferN
	m.mu.Unlock()

	logger.Metric("sched_jobs_total", float64(total), "count")
	logger.Metric("sched_timeout_count", float64(atomic.LoadInt64(&m.scheduleTimeouts)), "count")
	logger.Metric("sched_panic_count", float64(atomic.LoadInt64(&m.jobPanics)), "count")
	if queueN > 0 {
		logger.Metric("sched_queue_wait_avg_ms", float64(queueTotal.Milliseconds())/float64(queueN), "ms")
		logger.Metric("sched_queue_wait_max_ms", float64(queueMax.Milliseconds()), "ms")
	}
	if lockN > 0 {
		logger.Metric("sched_lock_wait_avg_ms", float64(lockTotal.Milliseconds())/float64(lockN), "ms")
		logger.Metric("sched_lock_wait_max_ms", float64(lockMax.Milliseconds()), "ms")
	}
	if execN > 0 {
		logger.Metric("sched_execution_avg_ms", float64(execTotal.Milliseconds())/float64(execN), "ms")
		logger.Metric("sched_execution_max_ms", float64(execMax.Milliseconds()), "ms")
	}
	if admissionN > 0 {
		logger.Metric("sched_admission_allowed_count", float64(admissionN), "count")
		logger.Metric("sched_admission_deferred_count", float64(deferN), "count")
		if deferN > 0 {
			logger.Metric("sched_admission_defer_wait_avg_ms", float64(deferTotal.Milliseconds())/float64(deferN), "ms")
			logger.Metric("sched_admission_defer_wait_max_ms", float64(deferMax.Milliseconds()), "ms")
		}
	}
}

// gaugeSampleInterval is deliberately coarse: a Full Sweep can run for a long
// time, and nothing consumes these gauges in real time yet -- they exist to
// be looked at after the fact, not polled.
const gaugeSampleInterval = 5 * time.Second

// runGaugeSampler periodically reports the scheduler's in-flight state --
// jobs dispatched but not finished (active) and jobs not yet dispatched
// (queued) -- while a run is in progress. started/finished are the caller's
// own atomic counters, incremented at well-defined points around each job's
// Run (see runScenario). Sampling stops as soon as done is closed. interval
// is a parameter (rather than always gaugeSampleInterval) purely so tests
// can drive it fast without a 5-second sleep.
func runGaugeSampler(logger metricSink, started, finished *int64, total int, interval time.Duration, done <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			s := atomic.LoadInt64(started)
			f := atomic.LoadInt64(finished)
			logger.Metric("sched_active_jobs", float64(s-f), "count")
			logger.Metric("sched_queued_jobs", float64(int64(total)-s), "count")
		}
	}
}
