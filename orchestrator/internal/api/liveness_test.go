package api

import (
	"testing"
	"time"
)

func TestRunIsStale(t *testing.T) {
	now := time.Now()
	recentStart := now.Add(-1 * time.Minute)

	// Agent alive (fresh heartbeat) + recent run → not stale.
	if runIsStale(recentStart, now.Add(-10*time.Second), now) {
		t.Error("alive agent + recent run must not be stale")
	}
	// Agent offline (stale heartbeat) → stale immediately, even though run is recent.
	if !runIsStale(recentStart, now.Add(-5*time.Minute), now) {
		t.Error("offline agent must make its run stale immediately")
	}
	// Agent alive but run exceeds the hard ceiling → stale (backstop).
	if !runIsStale(now.Add(-3*time.Hour), now.Add(-5*time.Second), now) {
		t.Error("run beyond staleRunGuard ceiling must be stale")
	}
}
