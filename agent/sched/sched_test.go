package sched

import (
	"context"
	"math/rand"
	"sync"
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
	if got["registry"] != false || got["filesystem/C:\\temp"] != false {
		t.Errorf("observation domains should be read locks: %v", got)
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

func TestResolveGlobalScopeIsExclusive(t *testing.T) {
	got := keyMode(resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "wmi-secpolicy"}},
		Scope:   "global", Risk: RiskModification,
	}))
	if len(got) != 1 || got[globalKey] != true {
		t.Errorf("global-scope step must resolve to a single exclusive global lock, got %v", got)
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
		if len(got) != 1 || got[globalKey] != true {
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
		jobs[i] = Job{Resource: p, Run: func(ctx context.Context) {
			tr.enter()
			time.Sleep(25 * time.Millisecond)
			tr.leave()
		}}
	}
	return jobs
}

func TestObservationSameDomainRunsConcurrently(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskObservation}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr))
	if tr.peak() < 2 {
		t.Errorf("read-only steps on the same domain must run in parallel; peak concurrency was %d", tr.peak())
	}
}

func TestModificationSameDomainSerializes(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskModification}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr))
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
	Run(context.Background(), 4, lm, jobs)
	if tr.peak() < 2 {
		t.Errorf("writes to disjoint domains must run in parallel; peak concurrency was %d", tr.peak())
	}
}

func TestGlobalScopeSerializes(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Scope: "global", Risk: RiskModification}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr))
	if tr.peak() != 1 {
		t.Errorf("global-scope steps must run one at a time; peak concurrency was %d", tr.peak())
	}
}

func TestNilProfileSerializes(t *testing.T) {
	tr := &tracker{}
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, nil, tr))
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
		jobs = append(jobs, Job{Resource: p, Run: func(ctx context.Context) {
			mu.Lock()
			done++
			mu.Unlock()
		}})
	}

	doneCh := make(chan struct{})
	go func() { Run(context.Background(), 8, NewLockManager(), jobs); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("scheduler deadlocked: jobs did not complete within 10s")
	}
	if done != len(jobs) {
		t.Errorf("expected all %d jobs to run, got %d", len(jobs), done)
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
		jobs[i] = Job{Run: func(ctx context.Context) {
			mu.Lock()
			ran++
			mu.Unlock()
			cancel() // cancel after the first job starts
			time.Sleep(2 * time.Millisecond)
		}}
	}
	Run(ctx, 1, NewLockManager(), jobs)
	mu.Lock()
	defer mu.Unlock()
	if ran == len(jobs) {
		t.Errorf("cancellation should have skipped remaining jobs, but all %d ran", ran)
	}
}
