package main

import (
	"testing"
	"time"
)

func TestDisconnectedForReportsZeroWhenConnected(t *testing.T) {
	a := &Agent{} // disconnectedSince zero = connected
	if d := a.disconnectedFor(); d != 0 {
		t.Errorf("disconnectedFor while connected = %v, want 0", d)
	}
}

func TestDisconnectedForMeasuresOutage(t *testing.T) {
	a := &Agent{}
	a.disconnectedSince = time.Now().Add(-100 * time.Second)
	if d := a.disconnectedFor(); d < 90*time.Second {
		t.Errorf("disconnectedFor after a 100s outage = %v, want >= 90s", d)
	}
}

// The grace period the watchdog enforces must match the server's offline-after
// threshold, so the agent finalizes its own run exactly as the server would mark it.
func TestDisconnectGracePeriodMatchesServerOfflineWindow(t *testing.T) {
	if disconnectGracePeriod != 90*time.Second {
		t.Errorf("disconnectGracePeriod = %v, want 90s (server AgentOfflineAfter)", disconnectGracePeriod)
	}
}
