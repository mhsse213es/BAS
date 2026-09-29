package sched

import (
	"context"
	"sync/atomic"
	"testing"
)

// TestRun_FalseReturnFromOneJobDoesNotPreventSiblingsFromRunning locks in
// the exact scheduler guarantee agent.go's B5 veto check (and its
// existing circuit-breaker/payload-quarantine neighbors) relies on: a
// job's Run closure returning false only marks THAT job non-retrying --
// it never stops the scheduler from invoking every other job's Run
// closure.
func TestRun_FalseReturnFromOneJobDoesNotPreventSiblingsFromRunning(t *testing.T) {
	var vetoedRan, siblingRan int32
	jobs := []Job{
		{Run: func(ctx context.Context) bool {
			atomic.AddInt32(&vetoedRan, 1)
			return false
		}},
		{Run: func(ctx context.Context) bool {
			atomic.AddInt32(&siblingRan, 1)
			return true
		}},
	}
	Run(context.Background(), 2, NewLockManager(), jobs, nil)

	if atomic.LoadInt32(&vetoedRan) != 1 {
		t.Error("the vetoed job's Run was not invoked")
	}
	if atomic.LoadInt32(&siblingRan) != 1 {
		t.Error("a false return from one job's Run prevented a sibling job's Run from executing")
	}
}
