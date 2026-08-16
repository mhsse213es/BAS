package sched

import "context"
import "sync"

// Gate lets a caller pause/resume a Run in progress without touching ctx. A
// paused Gate blocks workers from starting their NEXT job; any job already
// inside its Run func is never interrupted -- it always runs to completion.
// Safe for concurrent use. A nil *Gate is a valid, always-unpaused no-op
// (Wait returns immediately), so sched.Run callers that don't need pause
// support can pass nil.
type Gate struct {
	mu     sync.Mutex
	paused bool
	ch     chan struct{} // closed while NOT paused; replaced with a fresh (open) channel on Pause
}

// NewGate returns a Gate that starts in the unpaused state.
func NewGate() *Gate {
	g := &Gate{ch: make(chan struct{})}
	close(g.ch)
	return g
}

// Pause is idempotent -- pausing an already-paused Gate is a no-op.
func (g *Gate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return
	}
	g.paused = true
	g.ch = make(chan struct{})
}

// Resume is idempotent -- resuming an already-unpaused Gate is a no-op.
func (g *Gate) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.paused {
		return
	}
	g.paused = false
	close(g.ch)
}

func (g *Gate) IsPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

// Wait blocks until the Gate is resumed or ctx is done, whichever comes
// first. Returns immediately if the Gate is not currently paused. Safe to
// call on a nil *Gate (returns immediately).
func (g *Gate) Wait(ctx context.Context) {
	if g == nil {
		return
	}
	g.mu.Lock()
	ch := g.ch
	g.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
	}
}
