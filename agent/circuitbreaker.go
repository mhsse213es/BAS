package main

import (
	"sync"

	"audspect/agent/sched"
)

// circuitBreaker tracks consecutive terminal-outcome failures per key,
// blocking new work against a key once it trips. Constructed fresh per
// scenario run (see runScenario) -- same per-run lifecycle as
// ConcurrencyLimiter and RiskGate, so a breaker that opened due to a bad
// run self-heals for the next run with no staleness risk.
type circuitBreaker struct {
	mu          sync.Mutex
	threshold   int
	consecutive map[string]int
	open        map[string]bool
}

// circuitBreakerThreshold: consecutive terminal-outcome failures against the
// same key before its breaker opens. One fixed value shared by both the
// technique and domain keyspaces -- risk-based retry (Phase 7) already
// differentiates Observation vs Modification's own retry budget; scaling
// this threshold by risk too would add complexity with no evidence behind
// it.
const circuitBreakerThreshold = 3

func newCircuitBreaker(threshold int) *circuitBreaker {
	return &circuitBreaker{
		threshold:   threshold,
		consecutive: make(map[string]int),
		open:        make(map[string]bool),
	}
}

// isOpen reports whether key's breaker is currently tripped.
func (b *circuitBreaker) isOpen(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open[key]
}

// anyOpen reports whether any of keys' breakers is currently tripped --
// blocking a step if even one of the domains/technique it touches is known
// broken this run, the same conservative default already used for locking.
func (b *circuitBreaker) anyOpen(keys []string) bool {
	for _, k := range keys {
		if b.isOpen(k) {
			return true
		}
	}
	return false
}

// recordOutcome updates key's consecutive-failure count from a Job's
// terminal outcome (never called per individual retry attempt -- only once
// a step's own Phase 7 retry sequence is genuinely done). success resets
// the count to 0; a failure increments it and opens the breaker once it
// reaches threshold.
func (b *circuitBreaker) recordOutcome(key string, success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if success {
		b.consecutive[key] = 0
		b.open[key] = false
		return
	}
	b.consecutive[key]++
	if b.consecutive[key] >= b.threshold {
		b.open[key] = true
	}
}

// recordAll records the same terminal outcome against every one of keys.
func (b *circuitBreaker) recordAll(keys []string, success bool) {
	for _, k := range keys {
		b.recordOutcome(k, success)
	}
}

// breakerKeysForStep returns every circuit-breaker key a step participates
// in: its technique, plus one key per declared resource domain. A step with
// no curated ResourceProfile or no declared Domains still gets its
// technique key -- the domain axis only participates when domains are
// actually declared.
//
// This only covers the Domains form of ResourceProfile. A profile using the
// newer Reads/Writes form (which takes precedence over Domains when
// populated, per ResourceProfile's own doc comment) gets no domain-scoped
// breaker key today, only its technique key. That is a known, currently
// latent gap -- no production code populates Reads/Writes yet -- not an
// intentional mirror of ResourceProfile's own precedence behavior.
func breakerKeysForStep(techniqueID string, p *sched.ResourceProfile) []string {
	keys := []string{"technique:" + techniqueID}
	if p == nil {
		return keys
	}
	for _, d := range p.Domains {
		keys = append(keys, "domain:"+d.Domain)
	}
	return keys
}
