package api

import (
	"testing"
	"time"
)

func TestEffectiveAgentStatus(t *testing.T) {
	now := time.Now()

	// Fresh heartbeat → keep the stored connectivity status.
	if got := effectiveAgentStatus("scanning", now.Add(-10*time.Second), now); got != "scanning" {
		t.Errorf("fresh scanning: got %q, want scanning", got)
	}
	if got := effectiveAgentStatus("idle", now.Add(-30*time.Second), now); got != "idle" {
		t.Errorf("fresh idle: got %q, want idle", got)
	}

	// Stale heartbeat → offline regardless of the stored status.
	if got := effectiveAgentStatus("scanning", now.Add(-5*time.Minute), now); got != "offline" {
		t.Errorf("stale scanning: got %q, want offline", got)
	}
	if got := effectiveAgentStatus("offline", now.Add(-5*time.Minute), now); got != "offline" {
		t.Errorf("stale offline: got %q, want offline", got)
	}
}

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
