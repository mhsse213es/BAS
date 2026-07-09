package testutil

import (
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"
)

// FrozenClock is an injectable time source for tests that need
// deterministic timestamps. Production code must accept a func() time.Time
// (or equivalent) rather than calling time.Now() directly for this to
// apply — Phase 0 does not retrofit production code with that seam.
type FrozenClock struct {
	now atomic.Int64 // unix nanos
}

// NewFrozenClock returns a clock fixed at t.
func NewFrozenClock(t time.Time) *FrozenClock {
	c := &FrozenClock{}
	c.now.Store(t.UnixNano())
	return c
}

// Now returns the clock's current fixed time.
func (c *FrozenClock) Now() time.Time {
	return time.Unix(0, c.now.Load())
}

// Advance moves the clock forward by d.
func (c *FrozenClock) Advance(d time.Duration) {
	c.now.Add(int64(d))
}

// SeqUUID is a deterministic, seedable stand-in for uuid generation in
// tests — produces predictable ids like "test-000000000001" instead of
// random ones, so assertions and golden files stay stable.
type SeqUUID struct {
	prefix string
	n      atomic.Uint64
}

// NewSeqUUID returns a generator whose Next() calls produce
// "<prefix>-<12-digit sequence>" starting after seed.
func NewSeqUUID(prefix string, seed uint64) *SeqUUID {
	g := &SeqUUID{prefix: prefix}
	g.n.Store(seed)
	return g
}

// Next returns the next id in sequence.
func (g *SeqUUID) Next() string {
	n := g.n.Add(1)
	return fmt.Sprintf("%s-%012d", g.prefix, n)
}

// SeededRand returns a math/rand source seeded deterministically, for
// property-based tests that need a reproducible "random" input on failure.
func SeededRand(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}
