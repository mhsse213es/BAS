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
}

// Run executes jobs across `workers` goroutines, holding each job's resource
// locks for the duration of its Run so that conflicting jobs never overlap.
// Non-conflicting jobs run concurrently. Jobs are dispatched in submission order
// but may start and finish in any order. Run blocks until all jobs complete (or,
// once ctx is cancelled, until in-flight jobs drain — remaining jobs are skipped).
//
// Deadlock-freedom: a job in the queue holds no locks, so no running job can ever
// wait on a lock held by a not-yet-started job; combined with canonical-order
// acquisition (see resolve/LockManager), the scheduler cannot deadlock.
func Run(ctx context.Context, workers int, lm *LockManager, jobs []Job) {
	if workers < 1 {
		workers = 1
	}
	if lm == nil {
		lm = NewLockManager()
	}
	ch := make(chan Job)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				if ctx.Err() != nil {
					continue // cancelled: drain the channel without running
				}
				runJob(ctx, lm, j)
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
func runJob(ctx context.Context, lm *LockManager, j Job) {
	reqs := resolve(j.Resource)

	acqCtx, cancel := ctx, context.CancelFunc(func() {})
	if j.Schedule > 0 {
		acqCtx, cancel = context.WithTimeout(ctx, j.Schedule)
	}
	ok := lm.AcquireCtx(acqCtx, reqs)
	cancel()
	if !ok {
		// AcquireCtx failed: a cancelled scenario (ctx done) is a normal abort —
		// skip silently. Otherwise the schedule timeout fired: record it so the
		// step is never silently stuck.
		if ctx.Err() == nil && j.OnScheduleTimeout != nil {
			j.OnScheduleTimeout()
		}
		return
	}

	defer lm.Release(reqs)
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[sched] recovered panic in step: %v", p)
		}
	}()
	if j.Run != nil {
		j.Run(ctx)
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
