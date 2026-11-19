package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A running agent must re-check its certificate on a timer, not only at process start (audit F-06).
func TestRunPeriodic_RunsImmediatelyThenOnEachTickUntilCancelled(t *testing.T) {
	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runPeriodic(ctx, 10*time.Millisecond, func(context.Context) { atomic.AddInt32(&calls, 1) })
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runPeriodic did not stop after the context was cancelled")
	}
	if n := atomic.LoadInt32(&calls); n < 3 {
		t.Fatalf("expected at least 3 calls (one at start, then each tick), got %d", n)
	}
}
