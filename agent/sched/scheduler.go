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
// are captured by the caller via the closure, so Run returns nothing.
type Job struct {
	Resource *ResourceProfile
	Run      func(ctx context.Context)
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
// acquisition (see resolve/LockManager), the scheduler cannot deadlock.
//
// rec, if provided (at most one -- trailing variadic so every existing caller
// and test is source-compatible), receives per-job telemetry. See Recorder.
// Run and runJob never branch on it: it is pure observation, added to measure
// the scheduler before any adaptive admission layer is built on top of it.
func Run(ctx context.Context, workers int, lm *LockManager, jobs []Job, gate *Gate, rec ...Recorder) {
	if workers < 1 {
		workers = 1
	}
	if lm == nil {
		lm = NewLockManager()
	}
	var r Recorder
	if len(rec) > 0 {
		r = rec[0]
	}
	ch := make(chan Job)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				if r != nil && !j.Queued.IsZero() {
					// Measured at dequeue, before the pause gate: this is contention
					// for a free worker, not the operator's deliberate pause.
					r.QueueWait(time.Since(j.Queued))
				}
				if ctx.Err() != nil {
					continue // cancelled: drain the channel without running
				}
				gate.Wait(ctx) // blocks here while paused; no-op if gate is nil or unpaused
				if ctx.Err() != nil {
					continue // cancel can race with a pause -- re-check before running
				}
				runJob(ctx, lm, j, r)
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
func runJob(ctx context.Context, lm *LockManager, j Job, rec Recorder) {
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
		// step is never silently stuck.
		if ctx.Err() == nil && j.OnScheduleTimeout != nil {
			if rec != nil {
				rec.ScheduleTimeout()
			}
			j.OnScheduleTimeout()
		}
		return
	}

	defer lm.Release(reqs)
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[sched] recovered panic in step: %v", p)
			if rec != nil {
				rec.JobPanic()
			}
		}
	}()
	if j.Run != nil {
		execStart := time.Now()
		j.Run(ctx)
		if rec != nil {
			rec.ExecutionTime(time.Since(execStart))
		}
	}
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
