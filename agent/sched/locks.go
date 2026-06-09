package sched

import (
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
func resolve(p *ResourceProfile) []lockReq {
	writes := map[string]bool{} // lock key -> needs exclusive hold

	if p == nil || p.Scope == "global" || len(p.Domains) == 0 || !knownRisk(p.Risk) {
		// Unlabeled / global / unrecognised → exclusive global barrier → serial.
		writes[globalKey] = true
	} else {
		writes[globalKey] = false // shared barrier: coexists with other scoped steps
		exclusive := p.Risk != RiskObservation
		for _, d := range p.Domains {
			k := d.Domain
			if d.Key != "" {
				k += "/" + d.Key
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

// Acquire blocks until every lock in reqs is held. reqs must be sorted (resolve
// guarantees this); acquiring in a single global order across all goroutines is
// what makes the scheduler deadlock-free.
func (m *LockManager) Acquire(reqs []lockReq) {
	for _, r := range reqs {
		l := m.mutex(r.key)
		if r.write {
			l.Lock()
		} else {
			l.RLock()
		}
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
