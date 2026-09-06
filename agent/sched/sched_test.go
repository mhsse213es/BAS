package sched

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── resolve() ────────────────────────────────────────────────────────────────

func keyMode(reqs []lockReq) map[string]bool {
	m := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		m[r.key] = r.write
	}
	return m
}

func TestResolveObservationTakesReadLocks(t *testing.T) {
	got := keyMode(resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "registry"}, {Domain: "filesystem", Key: "C:\\temp"}},
		Scope:   "local", Risk: RiskObservation,
	}))
	if got[globalKey] != false {
		t.Errorf("global barrier should be shared (read) for a scoped step, got write=%v", got[globalKey])
	}
	// Assert PRESENCE as well as mode. `got[k] != false` alone passes vacuously
	// for a key that isn't there at all, since a missing map entry reads as
	// false — which silently hid the canonical spelling of the filesystem key.
	for _, k := range []string{"registry", "filesystem/c:/temp"} {
		mode, present := got[k]
		if !present {
			t.Errorf("expected a lock on %q, got %v", k, got)
			continue
		}
		if mode != false {
			t.Errorf("observation domain %q should be a read lock, got write=%v", k, mode)
		}
	}
}

func TestResolveModificationTakesWriteLocks(t *testing.T) {
	got := keyMode(resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "registry"}},
		Scope:   "local", Risk: RiskModification,
	}))
	if got[globalKey] != false {
		t.Errorf("scoped step should hold the global barrier shared, got write=%v", got[globalKey])
	}
	if got["registry"] != true {
		t.Errorf("modification domain should be a write lock: %v", got)
	}
}

// isFullySerial reports whether a resolved lock set means "runs alone": the
// exclusive global barrier and no per-domain locks.
//
// The footprint barrier is expected alongside it and deliberately ignored here.
// Every step holds it — shared for ordinary execution — because an observer must
// exclude unlabeled steps too, or their processes contaminate its reading. These
// assertions used to be `len(got) != 1`, which conflated "holds no domain locks"
// with "holds exactly one lock"; the barrier makes the difference visible.
func isFullySerial(got map[string]bool) bool {
	if got[globalKey] != true {
		return false
	}
	for k := range got {
		if k != globalKey && k != footprintKey {
			return false // a per-domain lock means it is not running alone
		}
	}
	return true
}

func TestResolveGlobalScopeIsExclusive(t *testing.T) {
	got := keyMode(resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "wmi-secpolicy"}},
		Scope:   "global", Risk: RiskModification,
	}))
	if !isFullySerial(got) {
		t.Errorf("global-scope step must resolve to the exclusive global lock and no domain locks, got %v", got)
	}
}

func TestResolveDefaultsToSerial(t *testing.T) {
	cases := map[string]*ResourceProfile{
		"nil":           nil,
		"empty domains": {Scope: "local", Risk: RiskObservation},
		"unknown risk":  {Domains: []ResourceLock{{Domain: "registry"}}, Risk: "wat"},
	}
	for name, p := range cases {
		got := keyMode(resolve(p))
		if !isFullySerial(got) {
			t.Errorf("%s: must default to exclusive global lock (serial), got %v", name, got)
		}
	}
}

func TestResolveIsSorted(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "registry"}, {Domain: "filesystem"}, {Domain: "network"}},
		Scope:   "local", Risk: RiskObservation,
	})
	for i := 1; i < len(reqs); i++ {
		if reqs[i-1].key > reqs[i].key {
			t.Fatalf("lock requests not sorted: %q before %q", reqs[i-1].key, reqs[i].key)
		}
	}
}

// ── scheduler concurrency / isolation ────────────────────────────────────────

// tracker records the maximum number of jobs observed running simultaneously.
type tracker struct {
	mu       sync.Mutex
	cur, max int
}

func (c *tracker) enter() {
	c.mu.Lock()
	c.cur++
	if c.cur > c.max {
		c.max = c.cur
	}
	c.mu.Unlock()
}
func (c *tracker) leave() {
	c.mu.Lock()
	c.cur--
	c.mu.Unlock()
}
func (c *tracker) peak() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max
}

// jobs builds n jobs with the same profile that each register a brief overlap
// window on the tracker.
func makeJobs(n int, p *ResourceProfile, tr *tracker) []Job {
	jobs := make([]Job, n)
	for i := range jobs {
		jobs[i] = Job{Resource: p, Run: func(ctx context.Context) bool {
			tr.enter()
			time.Sleep(25 * time.Millisecond)
			tr.leave()
			return false
		}}
	}
	return jobs
}

func TestObservationSameDomainRunsConcurrently(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskObservation}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr), nil)
	if tr.peak() < 2 {
		t.Errorf("read-only steps on the same domain must run in parallel; peak concurrency was %d", tr.peak())
	}
}

func TestModificationSameDomainSerializes(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskModification}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr), nil)
	if tr.peak() != 1 {
		t.Errorf("writes to the same domain must serialize; peak concurrency was %d", tr.peak())
	}
}

func TestModificationDifferentDomainsRunConcurrently(t *testing.T) {
	tr := &tracker{}
	lm := NewLockManager()
	var jobs []Job
	for _, dom := range []string{"registry", "filesystem", "network", "process"} {
		p := &ResourceProfile{Domains: []ResourceLock{{Domain: dom}}, Scope: "local", Risk: RiskModification}
		jobs = append(jobs, makeJobs(1, p, tr)...)
	}
	Run(context.Background(), 4, lm, jobs, nil)
	if tr.peak() < 2 {
		t.Errorf("writes to disjoint domains must run in parallel; peak concurrency was %d", tr.peak())
	}
}

func TestGlobalScopeSerializes(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Scope: "global", Risk: RiskModification}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr), nil)
	if tr.peak() != 1 {
		t.Errorf("global-scope steps must run one at a time; peak concurrency was %d", tr.peak())
	}
}

func TestNilProfileSerializes(t *testing.T) {
	tr := &tracker{}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, nil, tr), nil)
	if tr.peak() != 1 {
		t.Errorf("unlabeled steps must default to serial; peak concurrency was %d", tr.peak())
	}
}

// TestRandomizedNoDeadlock submits many jobs with random profiles across many
// workers; with -race this also exercises lock ordering. All jobs must complete.
func TestRandomizedNoDeadlock(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	domains := []string{"registry", "filesystem", "network", "process", "wmi-secpolicy"}
	risks := []string{RiskObservation, RiskModification, RiskPersistence}
	var done int
	var mu sync.Mutex
	var jobs []Job
	for i := 0; i < 400; i++ {
		var p *ResourceProfile
		switch rng.Intn(4) {
		case 0:
			p = nil // serial
		case 1:
			p = &ResourceProfile{Scope: "global", Risk: RiskModification}
		default:
			n := 1 + rng.Intn(3)
			var ds []ResourceLock
			for j := 0; j < n; j++ {
				ds = append(ds, ResourceLock{Domain: domains[rng.Intn(len(domains))]})
			}
			p = &ResourceProfile{Domains: ds, Scope: "local", Risk: risks[rng.Intn(len(risks))]}
		}
		jobs = append(jobs, Job{Resource: p, Run: func(ctx context.Context) bool {
			mu.Lock()
			done++
			mu.Unlock()
			return false
		}})
	}

	doneCh := make(chan struct{})
	go func() { Run(context.Background(), 8, NewLockManager(), jobs, nil); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("scheduler deadlocked: jobs did not complete within 10s")
	}
	if done != len(jobs) {
		t.Errorf("expected all %d jobs to run, got %d", len(jobs), done)
	}
}

// ── timeout supervisor: cancellable acquire, panic safety, schedule timeout ───

// TestAcquireCtxTimesOutAndLeavesNoLeak proves a contended acquire gives up on
// ctx deadline AND that the abandoned attempt does not leak the lock: once the
// holder releases, the key is acquirable again.
func TestAcquireCtxTimesOutAndLeavesNoLeak(t *testing.T) {
	lm := NewLockManager()
	w := []lockReq{{key: "k", write: true}}

	if !lm.AcquireCtx(context.Background(), w) {
		t.Fatal("first acquire should succeed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if lm.AcquireCtx(ctx, w) {
		t.Fatal("second acquire of a held write lock must time out")
	}

	lm.Release(w) // releasing must make the key acquirable again (no leak)
	done := make(chan bool, 1)
	go func() { done <- lm.AcquireCtx(context.Background(), w) }()
	select {
	case ok := <-done:
		if !ok {
			t.Error("acquire after release returned false")
		}
		lm.Release(w)
	case <-time.After(2 * time.Second):
		t.Fatal("acquire after release blocked — a timed-out attempt leaked the lock")
	}
}

// TestRunJobReleasesLocksOnPanic verifies a panicking step is recovered (the agent
// does not crash) and its locks are released so a conflicting step still runs.
func TestRunJobReleasesLocksOnPanic(t *testing.T) {
	reg := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskModification}
	var ran2 bool
	jobs := []Job{
		{Resource: reg, Run: func(context.Context) bool { panic("boom") }},
		{Resource: reg, Run: func(context.Context) bool { ran2 = true; return false }},
	}
	Run(context.Background(), 2, NewLockManager(), jobs, nil)
	if !ran2 {
		t.Error("second job did not run — a panic leaked the registry write lock")
	}
}

// TestScheduleTimeoutFires verifies a step that cannot acquire its locks within
// its Schedule records a schedule timeout instead of blocking, and does not run.
func TestScheduleTimeoutFires(t *testing.T) {
	lm := NewLockManager()
	held := []lockReq{{key: globalKey, write: true}} // conflicts with every step
	if !lm.AcquireCtx(context.Background(), held) {
		t.Fatal("could not pre-hold the global barrier")
	}
	defer lm.Release(held)

	var toFired, ran bool
	job := Job{
		Resource:          &ResourceProfile{Scope: "global", Risk: RiskModification},
		Schedule:          20 * time.Millisecond,
		OnScheduleTimeout: func() { toFired = true },
		Run:               func(context.Context) bool { ran = true; return false },
	}
	Run(context.Background(), 1, lm, []Job{job}, nil)
	if !toFired {
		t.Error("OnScheduleTimeout did not fire for a step that could not acquire its lock")
	}
	if ran {
		t.Error("step ran despite never acquiring its lock")
	}
}

// TestScheduleTimeoutNotFiredOnCancel verifies a scenario abort (ctx cancelled) is
// NOT misreported as a schedule timeout.
func TestScheduleTimeoutNotFiredOnCancel(t *testing.T) {
	lm := NewLockManager()
	held := []lockReq{{key: globalKey, write: true}}
	lm.AcquireCtx(context.Background(), held)
	defer lm.Release(held)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // scenario already aborted

	var toFired bool
	runJob(ctx, lm, Job{
		Resource:          &ResourceProfile{Scope: "global", Risk: RiskModification},
		Schedule:          20 * time.Millisecond,
		OnScheduleTimeout: func() { toFired = true },
		Run:               func(context.Context) bool { return false },
	}, nil)
	if toFired {
		t.Error("schedule timeout fired on a cancelled scenario — abort misreported as timeout")
	}
}

// TestCancellationStopsDispatch verifies that cancelling the context prevents
// not-yet-started jobs from running.
func TestCancellationStopsDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ran int
	var mu sync.Mutex
	jobs := make([]Job, 100)
	for i := range jobs {
		jobs[i] = Job{Run: func(ctx context.Context) bool {
			mu.Lock()
			ran++
			mu.Unlock()
			cancel() // cancel after the first job starts
			time.Sleep(2 * time.Millisecond)
			return false
		}}
	}
	Run(ctx, 1, NewLockManager(), jobs, nil)
	mu.Lock()
	defer mu.Unlock()
	if ran == len(jobs) {
		t.Errorf("cancellation should have skipped remaining jobs, but all %d ran", ran)
	}
}

func TestRun_GateHoldsNewJobsButFinishesInFlight(t *testing.T) {
	gate := NewGate()
	var started, finished int32
	firstStarted := make(chan struct{})
	release := make(chan struct{})

	jobs := []Job{
		{Run: func(ctx context.Context) bool {
			atomic.AddInt32(&started, 1)
			close(firstStarted)
			<-release // held "in flight" until the test says go
			atomic.AddInt32(&finished, 1)
			return false
		}},
		{Run: func(ctx context.Context) bool {
			atomic.AddInt32(&started, 1)
			atomic.AddInt32(&finished, 1)
			return false
		}},
	}

	done := make(chan struct{})
	// workers=1 -- deterministic: only one job can ever be "in flight" at a time.
	go func() { Run(context.Background(), 1, NewLockManager(), jobs, gate); close(done) }()

	<-firstStarted // job 1 is now executing
	gate.Pause()   // pause while job 1 is still in flight
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&started); got != 1 {
		t.Fatalf("started = %d, want 1 (job 2 must not start while paused)", got)
	}

	close(release) // let job 1 finish
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&finished); got != 1 {
		t.Fatalf("finished = %d, want 1 (job 1 finishes even though paused)", got)
	}
	if got := atomic.LoadInt32(&started); got != 1 {
		t.Fatalf("started = %d, want still 1 (job 2 must still be held)", got)
	}

	gate.Resume()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not complete after Resume")
	}
	if s, f := atomic.LoadInt32(&started), atomic.LoadInt32(&finished); s != 2 || f != 2 {
		t.Fatalf("started=%d finished=%d, want 2/2 after Resume", s, f)
	}
}

// TestRun_RiskGateDefersModificationUntilPolicyAdmits proves the full
// integration: a job whose effective risk the gate's current policy rejects
// must not start running until SetPolicy admits it, then proceeds normally
// through the existing lock/timeout machinery unchanged.
func TestRun_RiskGateDefersModificationUntilPolicyAdmits(t *testing.T) {
	gate := NewRiskGate()
	gate.SetPolicy(func(risk string) bool { return risk == RiskObservation })

	started := make(chan struct{})
	job := Job{
		Resource: &ResourceProfile{Scope: "local", Risk: RiskModification},
		Run: func(ctx context.Context) bool {
			close(started)
			return false
		},
	}

	done := make(chan struct{})
	go func() {
		Run(context.Background(), 1, NewLockManager(), []Job{job}, nil, WithRiskGate(gate))
		close(done)
	}()

	select {
	case <-started:
		t.Fatal("job started despite RiskGate policy rejecting its risk classification")
	case <-time.After(30 * time.Millisecond):
		// expected: still blocked
	}

	gate.SetPolicy(func(risk string) bool { return true })

	select {
	case <-started:
		// expected
	case <-time.After(1 * time.Second):
		t.Fatal("job never started after SetPolicy admitted its risk classification")
	}
	<-done
}

// TestRun_NilRiskGateIsSafe proves the existing (pre-Phase-5) call shape --
// Run without WithRiskGate -- still works unmodified.
func TestRun_NilRiskGateIsSafe(t *testing.T) {
	ran := false
	jobs := []Job{{Run: func(ctx context.Context) bool { ran = true; return false }}}
	Run(context.Background(), 1, NewLockManager(), jobs, nil) // no WithRiskGate at all
	if !ran {
		t.Error("job did not run")
	}
}

// TestRun_RiskGateRecordsAdmissionWaitViaRecorder proves Run's worker loop
// actually reports AdmissionWait to a configured Recorder when a RiskGate is
// also configured -- not just that the job eventually runs (already proven
// above), but that the observability hook fires.
func TestRun_RiskGateRecordsAdmissionWaitViaRecorder(t *testing.T) {
	rec := &fakeRecorder{}
	gate := NewRiskGate() // default policy: admits everything immediately
	jobs := []Job{
		{Resource: &ResourceProfile{Risk: RiskObservation}, Run: func(ctx context.Context) bool { return false }},
		{Resource: &ResourceProfile{Risk: RiskModification}, Run: func(ctx context.Context) bool { return false }},
	}
	Run(context.Background(), 2, NewLockManager(), jobs, nil, WithRecorder(rec), WithRiskGate(gate))

	_, _, _, admission, _, _ := rec.snapshot()
	if admission != 2 {
		t.Errorf("AdmissionWait recorded %d times, want 2 (once per job that passed through the configured RiskGate)", admission)
	}
}
