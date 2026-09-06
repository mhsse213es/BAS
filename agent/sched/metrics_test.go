package sched

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeRecorder is a test double for Recorder, safe for concurrent use since
// Run invokes it from multiple worker goroutines.
type fakeRecorder struct {
	mu             sync.Mutex
	queueWaits     []time.Duration
	lockWaits      []time.Duration
	execTimes      []time.Duration
	admissionWaits []time.Duration
	timeouts       int
	panics         int
	retries        int
}

func (f *fakeRecorder) QueueWait(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queueWaits = append(f.queueWaits, d)
}

func (f *fakeRecorder) LockWait(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lockWaits = append(f.lockWaits, d)
}

func (f *fakeRecorder) ExecutionTime(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execTimes = append(f.execTimes, d)
}

func (f *fakeRecorder) ScheduleTimeout() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timeouts++
}

func (f *fakeRecorder) JobPanic() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panics++
}

func (f *fakeRecorder) AdmissionWait(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admissionWaits = append(f.admissionWaits, d)
}

func (f *fakeRecorder) Retry() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retries++
}

func (f *fakeRecorder) snapshot() (queue, lock, exec, admission int, timeouts, panics, retries int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queueWaits), len(f.lockWaits), len(f.execTimes), len(f.admissionWaits), f.timeouts, f.panics, f.retries
}

func TestFakeRecorder_AdmissionWait(t *testing.T) {
	f := &fakeRecorder{}
	f.AdmissionWait(5 * time.Millisecond)
	f.AdmissionWait(50 * time.Millisecond)
	_, _, _, admission, _, _, _ := f.snapshot()
	if admission != 2 {
		t.Errorf("admission wait count = %d, want 2", admission)
	}
}

// TestRun_RecordsQueueLockAndExecutionForEverySuccessfulJob proves the three
// per-job durations are all reported exactly once per job that runs to
// completion, and that QueueWait reflects real elapsed time (the job's Queued
// timestamp was set slightly in the past).
func TestRun_RecordsQueueLockAndExecutionForEverySuccessfulJob(t *testing.T) {
	rec := &fakeRecorder{}
	const n = 5
	jobs := make([]Job, n)
	for i := range jobs {
		jobs[i] = Job{
			Queued: time.Now().Add(-10 * time.Millisecond),
			Run:    func(ctx context.Context) bool { time.Sleep(time.Millisecond); return false },
		}
	}
	Run(context.Background(), 2, NewLockManager(), jobs, nil, WithRecorder(rec))

	q, l, e, _, timeouts, panics, _ := rec.snapshot()
	if q != n {
		t.Errorf("QueueWait calls = %d, want %d", q, n)
	}
	if l != n {
		t.Errorf("LockWait calls = %d, want %d", l, n)
	}
	if e != n {
		t.Errorf("ExecutionTime calls = %d, want %d", e, n)
	}
	if timeouts != 0 || panics != 0 {
		t.Errorf("timeouts=%d panics=%d, want 0/0", timeouts, panics)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, d := range rec.queueWaits {
		if d < 5*time.Millisecond {
			t.Errorf("QueueWait = %s, want >= ~10ms (Queued was set in the past)", d)
		}
	}
}

// TestRun_ScheduleTimeoutReportsLockWaitButNotExecutionTime proves a job whose
// locks are held by another job and whose Schedule bound expires is counted
// as a ScheduleTimeout, still reports the (failed) LockWait it spent trying,
// and never reports ExecutionTime since Run never started.
func TestRun_ScheduleTimeoutReportsLockWaitButNotExecutionTime(t *testing.T) {
	rec := &fakeRecorder{}
	lm := NewLockManager()
	holderStarted := make(chan struct{})
	releaseHolder := make(chan struct{})

	holder := Job{
		Resource: &ResourceProfile{Scope: "global"},
		Queued:   time.Now(),
		Run: func(ctx context.Context) bool {
			close(holderStarted)
			<-releaseHolder
			return false
		},
	}
	waiter := Job{
		Resource: &ResourceProfile{Scope: "global"},
		Schedule: 20 * time.Millisecond,
		Queued:   time.Now(),
		OnScheduleTimeout: func() {
			// no-op: existence alone proves the timeout path fired
		},
	}

	done := make(chan struct{})
	go func() {
		Run(context.Background(), 2, lm, []Job{holder, waiter}, nil, WithRecorder(rec))
		close(done)
	}()

	<-holderStarted
	time.Sleep(100 * time.Millisecond) // let waiter's schedule timeout fire
	close(releaseHolder)
	<-done

	q, l, e, _, timeouts, _, _ := rec.snapshot()
	if q != 2 {
		t.Errorf("QueueWait calls = %d, want 2", q)
	}
	if l != 2 {
		t.Errorf("LockWait calls = %d, want 2 (holder succeeded, waiter timed out -- both attempted)", l)
	}
	if e != 1 {
		t.Errorf("ExecutionTime calls = %d, want 1 (only the holder actually ran)", e)
	}
	if timeouts != 1 {
		t.Errorf("ScheduleTimeout calls = %d, want 1", timeouts)
	}
}

// TestRun_JobPanicIsRecordedAndDoesNotCrashOrSkipExecutionTimeAccounting
// proves a panicking Run is recovered (matching runJob's existing contract)
// and reported via JobPanic, with no ExecutionTime double-report for the
// panicking job.
func TestRun_JobPanicIsRecorded(t *testing.T) {
	rec := &fakeRecorder{}
	jobs := []Job{
		{Run: func(ctx context.Context) bool { panic("boom") }},
		{Run: func(ctx context.Context) bool { return false /* fine */ }},
	}
	Run(context.Background(), 1, NewLockManager(), jobs, nil, WithRecorder(rec))

	_, _, e, _, _, panics, _ := rec.snapshot()
	if panics != 1 {
		t.Errorf("JobPanic calls = %d, want 1", panics)
	}
	if e != 1 {
		t.Errorf("ExecutionTime calls = %d, want 1 (only the non-panicking job)", e)
	}
}

// TestRun_NilRecorderIsSafe proves the existing (pre-Phase-2) call shape --
// Run without a trailing Recorder argument -- still works, so none of the
// scheduler's other call sites or tests need to change.
func TestRun_NilRecorderIsSafe(t *testing.T) {
	ran := false
	jobs := []Job{{Run: func(ctx context.Context) bool { ran = true; return false }}}
	Run(context.Background(), 1, NewLockManager(), jobs, nil) // no Recorder arg at all
	if !ran {
		t.Error("job did not run")
	}
}
