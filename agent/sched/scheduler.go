package sched

import (
	"context"
	"runtime"
	"sync"
)

// Job is one step the scheduler runs. Resource is the step's lock profile (nil →
// serial). Run performs the work and must honour ctx for cancellation; results
// are captured by the caller via the closure, so Run returns nothing.
type Job struct {
	Resource *ResourceProfile
	Run      func(ctx context.Context)
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
				reqs := resolve(j.Resource)
				lm.Acquire(reqs)
				func() {
					defer lm.Release(reqs)
					j.Run(ctx)
				}()
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
