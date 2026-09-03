package sched

import (
	"context"
	"sort"
	"sync"
)

// lockReq is one lock a step must hold while it executes. write distinguishes an
// exclusive (modification/persistence/global) hold from a shared (observation)
// hold on the same key.
type lockReq struct {
	key   string
	write bool
}

// resolve turns a step's ResourceProfile into the canonical, sorted set of locks
// it must hold. Every step takes the global barrier lock: shared for scoped
// steps, exclusive for global-scope or unlabeled steps. Scoped steps additionally
// take a per-(domain,key) lock — shared for observation, exclusive otherwise.
//
// Resolution is deterministic and the output is sorted by key, so every goroutine
// acquires overlapping locks in the same order — the scheduler cannot deadlock.
// lockKeyFor validates one declared resource against the domain vocabulary and
// returns its canonical lock key. ok=false means the declaration cannot be
// verified by THIS build and must escalate — never be trusted as written.
//
// Validation lives here, at the lock boundary, rather than only server-side
// where profiles are authored. Profiles cross a version boundary; if the agent
// accepted a key it cannot parse, the core invariant would hold only when server
// and agent versions agree, instead of holding locally and unconditionally.
func lockKeyFor(d ResourceLock) (string, bool) {
	kind, known := LookupDomain(d.Domain)
	if !known {
		return "", false
	}
	switch kind {
	case KindWholeDomain:
		// A key here means the author addressed the domain at a granularity it
		// is not registered for — the declaration does not mean what it says.
		if d.Key != "" {
			return "", false
		}
		return d.Domain, true
	case KindKeyed:
		ck, ok := CanonicaliseKey(d.Domain, d.Key)
		if !ok {
			return "", false // unparseable, or whole-domain access to a keyed domain
		}
		return d.Domain + "/" + ck, true
	}
	return "", false
}

// escalate returns the lock set for a declaration that cannot be trusted: the
// exclusive global barrier, i.e. fully serial. Always correct, never optimistic.
//
// The footprint hold is carried through rather than dropped — an escalated step
// still perturbs the observation surface, so a footprint observer must still
// exclude it.
func escalate(observesFootprint bool) []lockReq {
	return []lockReq{
		{key: footprintKey, write: observesFootprint},
		{key: globalKey, write: true},
	}
}

func resolve(p *ResourceProfile) []lockReq {
	writes := map[string]bool{} // lock key -> needs exclusive hold

	// Every step participates in the footprint barrier, including a fully-serial
	// one: an observer must exclude unlabeled steps too, or their processes
	// contaminate its reading. Shared for ordinary execution, exclusive for an
	// observer — see footprintKey, and do not invert this.
	writes[footprintKey] = p != nil && p.ObservesFootprint

	if p != nil && (len(p.Reads) > 0 || len(p.Writes) > 0) {
		// Per-atomic form: direction is declared per resource, so Domains/Risk
		// are not consulted at all.
		writes[globalKey] = false // shared barrier: coexists with other scoped steps
		for _, set := range []struct {
			resources []ResourceLock
			exclusive bool
		}{{p.Reads, false}, {p.Writes, true}} {
			for _, d := range set.resources {
				k, ok := lockKeyFor(d)
				if !ok {
					return escalate(writes[footprintKey])
				}
				// A write dominates a read of the same resource: one exclusive
				// hold, never a shared and an exclusive hold on one key.
				writes[k] = writes[k] || set.exclusive
			}
		}
	} else if p == nil || p.Scope == "global" || len(p.Domains) == 0 || !knownRisk(p.Risk) {
		// Unlabeled / global / unrecognised → exclusive global barrier → serial.
		writes[globalKey] = true
	} else {
		writes[globalKey] = false // shared barrier: coexists with other scoped steps
		exclusive := p.Risk != RiskObservation
		for _, d := range p.Domains {
			k, ok := lockKeyFor(d)
			if !ok {
				// One unverifiable resource condemns the whole profile: we cannot
				// know what else it touches, so it runs alone.
				return escalate(writes[footprintKey])
			}
			writes[k] = writes[k] || exclusive
		}
	}

	out := make([]lockReq, 0, len(writes))
	for k, w := range writes {
		out = append(out, lockReq{key: k, write: w})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// LockManager hands out resource locks keyed by domain. Locks are created lazily
// and live for the LockManager's lifetime. Callers must Acquire and Release the
// same request slice; both walk it in canonical order (Release in reverse), which
// together with resolve's sorting guarantees deadlock-free concurrent use.
type LockManager struct {
	mu    sync.Mutex
	locks map[string]*sync.RWMutex
}

// NewLockManager returns an empty manager.
func NewLockManager() *LockManager {
	return &LockManager{locks: make(map[string]*sync.RWMutex)}
}

func (m *LockManager) mutex(key string) *sync.RWMutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.locks[key]
	if l == nil {
		l = &sync.RWMutex{}
		m.locks[key] = l
	}
	return l
}

// AcquireCtx acquires every lock in reqs, in canonical (sorted) order, returning
// true once all are held. If ctx is cancelled (scenario abort) or its deadline
// fires (schedule timeout) before all locks are held, it releases any locks it
// already took — in reverse order — and returns false, having acquired nothing on
// net. Ordered acquisition across all goroutines is what keeps the scheduler
// deadlock-free; a background ctx makes this behave like an unbounded blocking
// acquire.
func (m *LockManager) AcquireCtx(ctx context.Context, reqs []lockReq) bool {
	for i, r := range reqs {
		if !tryLock(ctx, m.mutex(r.key), r.write) {
			for j := i - 1; j >= 0; j-- {
				rr := reqs[j]
				ll := m.mutex(rr.key)
				if rr.write {
					ll.Unlock()
				} else {
					ll.RUnlock()
				}
			}
			return false
		}
	}
	return true
}

// tryLock acquires l (write or read) but gives up if ctx is done first. Because
// sync.RWMutex has no cancellable Lock, the acquire runs in a goroutine; if ctx
// wins the race, a detached goroutine releases the lock the instant the abandoned
// acquire finally succeeds, so no lock is ever leaked.
func tryLock(ctx context.Context, l *sync.RWMutex, write bool) bool {
	acquired := make(chan struct{})
	go func() {
		if write {
			l.Lock()
		} else {
			l.RLock()
		}
		close(acquired)
	}()
	select {
	case <-acquired:
		return true
	case <-ctx.Done():
		go func() {
			<-acquired
			if write {
				l.Unlock()
			} else {
				l.RUnlock()
			}
		}()
		return false
	}
}

// Release releases every lock in reqs, in reverse order.
func (m *LockManager) Release(reqs []lockReq) {
	for i := len(reqs) - 1; i >= 0; i-- {
		r := reqs[i]
		l := m.mutex(r.key)
		if r.write {
			l.Unlock()
		} else {
			l.RUnlock()
		}
	}
}
