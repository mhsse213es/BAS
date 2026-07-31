package models

import (
	"testing"
	"time"
)

func TestEffectiveAgentStatus(t *testing.T) {
	now := time.Now()

	// Fresh heartbeat → keep the stored connectivity status.
	if got := EffectiveAgentStatus("scanning", now.Add(-10*time.Second), now); got != "scanning" {
		t.Errorf("fresh scanning: got %q, want scanning", got)
	}
	if got := EffectiveAgentStatus("idle", now.Add(-30*time.Second), now); got != "idle" {
		t.Errorf("fresh idle: got %q, want idle", got)
	}

	// Stale heartbeat → offline regardless of the stored status.
	if got := EffectiveAgentStatus("scanning", now.Add(-5*time.Minute), now); got != "offline" {
		t.Errorf("stale scanning: got %q, want offline", got)
	}
	if got := EffectiveAgentStatus("offline", now.Add(-5*time.Minute), now); got != "offline" {
		t.Errorf("stale offline: got %q, want offline", got)
	}
}
