package sched

import (
	"context"
	"log"
	"runtime"
	"sync"
	"time"
)

// Job is one step the scheduler runs. Resource is the step's lock profile (nil →
// serial). Run performs the work and must honour ctx for cancellation; results
// are captured by the caller via the closure.
type Job struct {
	Resource *ResourceProfile
	// Run performs the work and reports whether this attempt's outcome
	// warrants a retry (per the caller's own classification of what it ran --
	// sched has no opinion on what "retryable" means). Ignored once a Job's
	// retry budget is exhausted or the outcome already succeeded.
	Run      func(ctx context.Context) (shouldRetry bool)
	// Schedule bounds how long the job may wait to acquire its resource locks. On
	// expiry the job is not run and OnScheduleTimeout fires instead. 0 → wait as
	// long as needed (bounded in practice by the holders' execute timeouts).
	Schedule time.Duration
	// OnScheduleTimeout records a schedule-timeout verdict for the step when its
	// locks could not be acquired within Schedule. Never called on scenario abort.
	OnScheduleTimeout func()
	// Queued is when the caller submitted this job (before Run's dispatch loop
	// even starts), used only to report QueueWait to an optional Recorder. Zero
	// value simply skips that one report -- everything else about the job is
	// unaffected.
	Queued time.Time
	// Retry bounds how many times this Job's full admission-and-execute
	// cycle repeats on a retryable outcome. The zero value (MaxAttempts 0)
	// means exactly one attempt, identical to every Job before this phase.
	Retry RetryPolicy
}

// RunOption configures optional Run behavior. Each new cross-cutting concern
// (telemetry, admission control, and whatever Phase 4+ adds) gets its own
// With* constructor instead of a new positional parameter, so Run's core
// signature -- the deterministic (ctx, workers, lm, jobs, gate) correctness
// contract -- never has to change again.
type RunOption func(*runConfig)

type runConfig struct {
	rec      Recorder
	limiter  *ConcurrencyLimiter
	riskGate *RiskGate
}

// WithRecorder attaches a Recorder that receives per-job telemetry (see
// Recorder). Run and runJob never branch on it: it is pure observation.
func WithRecorder(rec Recorder) RunOption {
	return func(c *runConfig) { c.rec = rec }
}

// WithConcurrencyLimiter caps how many jobs may hold locks and execute at
// once, independent of `workers`. See ConcurrencyLimiter -- this is the
// admission layer: it decides how MUCH work runs, never whether two jobs may
// safely overlap (the lock system decides that, unconditionally, regardless
// of what the limiter allows through).
func WithConcurrencyLimiter(l *ConcurrencyLimiter) RunOption {
	return func(c *runConfig) { c.limiter = l }
}

// WithRiskGate attaches a RiskGate that must admit a job's effective risk
// classification before it proceeds to lock acquisition. Checked between the
// pause gate and the ConcurrencyLimiter, in that order: an operator pause
// always takes precedence, then risk-based deferral, then raw concurrency
// admission, then lock correctness -- each layer strictly narrows what the
// layer below it ever sees.
func WithRiskGate(g *RiskGate) RunOption {
	return func(c *runConfig) { c.riskGate = g }
}

// Run executes jobs across `workers` goroutines, holding each job's resource
// locks for the duration of its Run so that conflicting jobs never overlap.
// Non-conflicting jobs run concurrently. Jobs are dispatched in submission order
// but may start and finish in any order. Run blocks until all jobs complete (or,
// once ctx is cancelled, until in-flight jobs drain — remaining jobs are skipped).
//
// gate, if non-nil, is checked between jobs (never mid-job): while gate is
// paused, a worker that has just pulled its next job off the queue blocks in
// gate.Wait before starting it, so no NEW job starts while paused, but any
// job already running always finishes normally. Pass nil for the original
// (no pause support) behavior.
//
// Deadlock-freedom: a job in the queue holds no locks, so no running job can ever
// wait on a lock held by a not-yet-started job; combined with canonical-order
// acquisition (see resolve/LockManager), the scheduler cannot deadlock. A
// WithConcurrencyLimiter admission gate sits strictly before lock resolution
// in the per-job path below and never changes this: it can only delay a job
// that has not yet started, exactly like the worker channel itself.
func Run(ctx context.Context, workers int, lm *LockManager, jobs []Job, gate *Gate, opts ...RunOption) {
	if workers < 1 {
		workers = 1
	}
	if lm == nil {
		lm = NewLockManager()
	}
	var cfg runConfig
	for _, o := range opts {
		o(&cfg)
	}
	ch := make(chan Job)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				if cfg.rec != nil && !j.Queued.IsZero() {
					// Measured at dequeue, before the pause gate: this is contention
					// for a free worker, not the operator's deliberate pause.
					cfg.rec.QueueWait(time.Since(j.Queued))
				}
				if ctx.Err() != nil {
					continue // cancelled: drain the channel without running
				}
				gate.Wait(ctx) // blocks here while paused; no-op if gate is nil or unpaused
				if ctx.Err() != nil {
					continue // cancel can race with a pause -- re-check before running
				}

				maxAttempts := j.Retry.maxAttempts()
				for attempt := 1; attempt <= maxAttempts; attempt++ {
					if attempt > 1 {
						if cfg.rec != nil {
							cfg.rec.Retry()
						}
						// Backoff holds neither the admission slot nor the lock --
						// both were already released at the end of the prior
						// attempt below -- so a step backing off never idle-holds a
						// scarce resource other steps may be waiting on.
						select {
						case <-time.After(j.Retry.backoff(attempt - 1)):
						case <-ctx.Done():
						}
						if ctx.Err() != nil {
							break
						}
						gate.Wait(ctx)
						if ctx.Err() != nil {
							break
						}
					}

					if cfg.riskGate != nil {
						admissionStart := time.Now()
						if !cfg.riskGate.Allow(ctx, effectiveRisk(j.Resource)) {
							break // ctx cancelled while deferred
						}
						if cfg.rec != nil {
							cfg.rec.AdmissionWait(time.Since(admissionStart))
						}
					}

					var retry bool
					if cfg.limiter != nil {
						if !cfg.limiter.Acquire(ctx) {
							break // ctx cancelled while waiting for an admission slot
						}
						retry = runJob(ctx, lm, j, cfg.rec)
						cfg.limiter.Release()
					} else {
						retry = runJob(ctx, lm, j, cfg.rec)
					}
					if !retry || attempt == maxAttempts {
						break
					}
				}
			}
		}()
	}
	for i := range jobs {
		if ctx.Err() != nil {
			break
		}
		ch <- jobs[i]
	}
	close(ch)
	wg.Wait()
}

// runJob acquires a job's locks (bounded by its schedule timeout), runs it, and
// guarantees the locks are released — even if Run panics, so one faulty step can
// neither crash the agent nor wedge the scheduler by holding a lock forever.
func runJob(ctx context.Context, lm *LockManager, j Job, rec Recorder) (shouldRetry bool) {
	reqs := resolve(j.Resource)

	lockWaitStart := time.Now()
	acqCtx, cancel := ctx, context.CancelFunc(func() {})
	if j.Schedule > 0 {
		acqCtx, cancel = context.WithTimeout(ctx, j.Schedule)
	}
	ok := lm.AcquireCtx(acqCtx, reqs)
	cancel()
	if rec != nil {
		rec.LockWait(time.Since(lockWaitStart))
	}
	if !ok {
		// AcquireCtx failed: a cancelled scenario (ctx done) is a normal abort —
		// skip silently. Otherwise the schedule timeout fired: record it so the
		// step is never silently stuck. Either way, never retried -- contention
		// for a resource is not the step failing.
		if ctx.Err() == nil && j.OnScheduleTimeout != nil {
			if rec != nil {
				rec.ScheduleTimeout()
			}
			j.OnScheduleTimeout()
		}
		return false
	}

	defer lm.Release(reqs)
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[sched] recovered panic in step: %v", p)
			if rec != nil {
				rec.JobPanic()
			}
			shouldRetry = false
		}
	}()
	if j.Run != nil {
		execStart := time.Now()
		shouldRetry = j.Run(ctx)
		if rec != nil {
			rec.ExecutionTime(time.Since(execStart))
		}
	}
	return shouldRetry
}

// DefaultWorkers returns a sane worker count for an endpoint: one per CPU, capped
// so the agent never saturates a production host it shares with real workloads.
func DefaultWorkers() int {
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	if n > 16 {
		n = 16
	}
	return n
}
