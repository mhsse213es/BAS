package api

import (
	"testing"
	"time"
)

// A stopped waiter must return without writing. Before the stop seam existed,
// the waiter slept out its full window and then wrote through the shared pool,
// which is how a leaked run could land in another test's TRUNCATE.
func TestEmailGWWaiter_StopBeforeWindowEndsWritesNothing(t *testing.T) {
	stop := emailGWWaiterStopChan()
	done := make(chan struct{})
	go func() {
		waitForEmailGWWindow(time.Now().Add(time.Hour), stop)
		close(done)
	}()
	StopEmailGWWaiters()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waiter still sleeping after StopEmailGWWaiters; a leaked run would write into a later test")
	}
}

// Stopping one generation must not stop waiters started after it, so a later
// test's real run still completes.
func TestEmailGWWaiter_StopDoesNotAffectLaterWaiters(t *testing.T) {
	StopEmailGWWaiters()
	stop := emailGWWaiterStopChan()
	done := make(chan bool, 1)
	go func() {
		done <- waitForEmailGWWindow(time.Now().Add(20*time.Millisecond), stop)
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("a waiter started after the stop was cancelled; its window should have ended normally")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not finish its window")
	}
}
