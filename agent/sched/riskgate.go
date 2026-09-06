package sched

import (
	"context"
	"sync"
)

// RiskGate blocks a job until an externally-set policy admits its risk
// classification, or ctx is cancelled. Uses the same sync.Cond +
// ctx-bridge pattern ConcurrencyLimiter used before Phase 6 (see below)
// for the same reason: sync.Cond.Wait isn't itself cancellable. RiskGate
// answers a different question than ConcurrencyLimiter -- ConcurrencyLimiter
// asks "how many jobs may run"; RiskGate asks "is this kind of job eligible
// to run at all right now." The two compose independently and neither has
// any awareness of the other.
//
// sched has no notion of "pressure" -- the policy is an opaque predicate the
// caller (package main, which does know about pressure.Level) swaps in via
// SetPolicy whenever conditions change. This mirrors how ConcurrencyLimiter's
// SetLimit takes a plain int, with the Level -> int mapping (ceilingForLevel)
// living entirely in package main.
//
// Unlike ConcurrencyLimiter (which moved to an explicit FIFO ticket queue in
// Phase 6 -- see limiter.go), RiskGate deliberately keeps sync.Cond's
// broadcast-wake-all. The two types only look symmetric on the surface:
// ConcurrencyLimiter.Acquire allocates from a scarce, countable resource
// (active < limit), so which of several blocked callers wins a post-wakeup
// race is a genuine, real starvation risk -- one caller can in principle
// keep losing that race indefinitely. Allow's wait loop instead evaluates a
// pure predicate (policy(risk)) that consumes nothing; every waiter whose
// risk the new policy admits is independently and correctly woken by
// Broadcast, with zero contention between them. A FIFO grant here would
// actually be wrong: it would only wake one waiter at a time when several
// different risk classes might have simultaneously become eligible.
type RiskGate struct {
	mu     sync.Mutex
	cond   *sync.Cond
	policy func(risk string) bool
}

// NewRiskGate returns a gate that admits everything until SetPolicy narrows it.
func NewRiskGate() *RiskGate {
	g := &RiskGate{policy: func(string) bool { return true }}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// SetPolicy replaces the admission predicate and wakes every blocked Allow
// call so it can re-evaluate against the new policy immediately. A nil
// policy resets to admit-everything, the same as a freshly-constructed gate.
func (g *RiskGate) SetPolicy(policy func(risk string) bool) {
	if policy == nil {
		policy = func(string) bool { return true }
	}
	g.mu.Lock()
	g.policy = policy
	g.mu.Unlock()
	g.cond.Broadcast()
}

// Allow blocks until the current policy admits risk, or ctx is done.
// Returns false only on ctx cancellation -- identical abort semantics to
// ConcurrencyLimiter.Acquire and AcquireCtx: never a rejection with side
// effects, always treated as a scenario abort by the caller.
func (g *RiskGate) Allow(ctx context.Context, risk string) bool {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			g.mu.Lock()
			g.cond.Broadcast()
			g.mu.Unlock()
		case <-stop:
		}
	}()

	g.mu.Lock()
	defer g.mu.Unlock()
	for !g.policy(risk) {
		if ctx.Err() != nil {
			return false
		}
		g.cond.Wait()
	}
	return true
}

// RiskUnknown is the effective risk of a job with no curated ResourceProfile
// (nil Resource, or an empty Risk field) -- treated conservatively, the same
// way an unlabeled profile already resolves to an exclusive global lock for
// LOCKING purposes (see resolve() in locks.go). A step nobody has evidenced
// as read-only is not assumed safe to prioritize under pressure either.
const RiskUnknown = "unknown"

// EffectiveRisk resolves a job's risk classification for admission purposes.
// A Reads/Writes-populated profile also has no Risk field set today by
// convention (see ResourceProfile's own doc comment) -- no curated profile in
// this codebase currently uses that form, so in practice "empty Risk" means
// "no curated profile exists for this step," which is exactly the
// RiskUnknown case this function returns for. Exported (not just used
// internally by Run for RiskGate.Allow) because package main now needs it
// too, to choose a retry policy before a Job is even constructed (Phase 7).
func EffectiveRisk(p *ResourceProfile) string {
	if p == nil || p.Risk == "" {
		return RiskUnknown
	}
	return p.Risk
}
