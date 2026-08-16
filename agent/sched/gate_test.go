package sched

import (
	"context"
	"testing"
	"time"
)

func TestGate_WaitBlocksWhilePausedThenUnblocksOnResume(t *testing.T) {
	g := NewGate()
	g.Pause()
	done := make(chan struct{})
	go func() { g.Wait(context.Background()); close(done) }()

	select {
	case <-done:
		t.Fatal("Wait returned while paused")
	case <-time.After(50 * time.Millisecond):
	}

	g.Resume()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait did not return after Resume")
	}
}

func TestGate_WaitReturnsImmediatelyWhenNeverPaused(t *testing.T) {
	g := NewGate()
	done := make(chan struct{})
	go func() { g.Wait(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait blocked despite Gate never paused")
	}
}

func TestGate_WaitUnblocksOnContextCancelWhilePaused(t *testing.T) {
	g := NewGate()
	g.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Wait(ctx); close(done) }()

	select {
	case <-done:
		t.Fatal("Wait returned before cancel")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait did not return after ctx cancel")
	}
}

func TestGate_PauseAndResumeAreIdempotent(t *testing.T) {
	g := NewGate()
	g.Pause()
	g.Pause() // must not panic or misbehave on a second Pause
	g.Resume()
	g.Resume() // must not panic on a second Resume
	if g.IsPaused() {
		t.Fatal("IsPaused = true after Resume")
	}
}

func TestGate_NilGateWaitIsNoOp(t *testing.T) {
	var g *Gate
	done := make(chan struct{})
	go func() { g.Wait(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("nil Gate.Wait blocked")
	}
}
