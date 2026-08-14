package license

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetInitial_ThenCurrent(t *testing.T) {
	want := Info{State: StateGrace, DaysRemaining: 3}
	SetInitial(want)
	got := Current()
	if got.State != want.State || got.DaysRemaining != want.DaysRemaining {
		t.Errorf("Current() = %+v, want %+v", got, want)
	}
}

func TestStartMonitor_PicksUpStateChangeOnTick(t *testing.T) {
	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")
	writeLic := func(expiresAt string) {
		data, _ := json.Marshal(License{Customer: "Acme", ExpiresAt: expiresAt})
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}
	}

	// Start valid, well in the future.
	writeLic(time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02"))
	SetInitial(Info{State: StateValid})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

	// Flip the file to an already-locked license (deep in the past).
	writeLic(time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if Current().State == StateLocked {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Current().State never became StateLocked after license file changed; last seen: %+v", Current())
}

func TestStartMonitor_OnLockFiresExactlyOnceOnTransition(t *testing.T) {
	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")
	data, _ := json.Marshal(License{Customer: "Acme", ExpiresAt: time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02")})
	if err := os.WriteFile(licPath, data, 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	SetInitial(Info{State: StateGrace}) // start NOT locked, so the first tick is the transition

	var calls int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, func() { calls++ })

	time.Sleep(200 * time.Millisecond) // several ticks — onLock must still fire only once
	if calls != 1 {
		t.Errorf("onLock called %d times, want exactly 1", calls)
	}
}
