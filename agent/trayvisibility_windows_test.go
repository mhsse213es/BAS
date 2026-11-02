//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// trayVisibilityHarness isolates the marker file and replaces the real tray start/stop with counters.
func trayVisibilityHarness(t *testing.T) (starts, stops *int) {
	t.Helper()
	oldPath, oldStart, oldStop, oldHidden := trayHiddenMarkerPath, trayStartFunc, trayStopFunc, trayHidden.Load()
	dir := t.TempDir()
	trayHiddenMarkerPath = func() string { return filepath.Join(dir, "BASAgent", "tray.hidden") }
	s, p := 0, 0
	trayStartFunc = func() { s++ }
	trayStopFunc = func() { p++ }
	trayHidden.Store(false)
	t.Cleanup(func() {
		trayHiddenMarkerPath, trayStartFunc, trayStopFunc = oldPath, oldStart, oldStop
		trayHidden.Store(oldHidden)
	})
	return &s, &p
}

func markerExists() bool {
	_, err := os.Stat(trayHiddenMarkerPath())
	return err == nil
}

func TestApplyTrayPolicy_HideStopsTrayAndPersists(t *testing.T) {
	starts, stops := trayVisibilityHarness(t)
	applyTrayPolicy(true)
	if !trayHidden.Load() {
		t.Fatal("hidden flag not set")
	}
	if *stops != 1 || *starts != 0 {
		t.Fatalf("stops=%d starts=%d, want 1/0: hiding must stop the running tray and not start one", *stops, *starts)
	}
	if !markerExists() {
		t.Fatal("hidden state must be persisted so a service restart does not flash the icon")
	}
}

func TestApplyTrayPolicy_ShowStartsTrayAndClearsMarker(t *testing.T) {
	starts, stops := trayVisibilityHarness(t)
	applyTrayPolicy(true)
	*starts, *stops = 0, 0
	applyTrayPolicy(false)
	if trayHidden.Load() {
		t.Fatal("hidden flag still set")
	}
	if *starts != 1 || *stops != 0 {
		t.Fatalf("starts=%d stops=%d, want 1/0: showing must start the tray", *starts, *stops)
	}
	if markerExists() {
		t.Fatal("marker must be removed when the icon is shown again")
	}
}

// Every heartbeat repeats the policy; repeating the state we are already in must do nothing (no tray restarts every 30s).
func TestApplyTrayPolicy_IsIdempotent(t *testing.T) {
	starts, stops := trayVisibilityHarness(t)
	applyTrayPolicy(false) // already visible: no-op
	if *starts != 0 || *stops != 0 {
		t.Fatalf("visible->visible changed the tray: starts=%d stops=%d", *starts, *stops)
	}
	applyTrayPolicy(true)
	applyTrayPolicy(true)
	applyTrayPolicy(true)
	if *stops != 1 {
		t.Fatalf("stops=%d after three identical hide policies, want exactly 1", *stops)
	}
}

func TestLoadTrayHidden_ReadsPersistedState(t *testing.T) {
	trayVisibilityHarness(t)
	loadTrayHidden()
	if trayHidden.Load() {
		t.Fatal("no marker: must start visible")
	}
	applyTrayPolicy(true)
	trayHidden.Store(false) // simulate a service restart
	loadTrayHidden()
	if !trayHidden.Load() {
		t.Fatal("marker present: a restarted service must come up hidden before the first heartbeat")
	}
}

// While hidden, neither the launch path nor the watchdog may bring the icon back.
func TestTrayLaunchSuppressedWhileHidden(t *testing.T) {
	trayVisibilityHarness(t)
	trayHidden.Store(true)
	if !shouldSkipTrayLaunch() {
		t.Fatal("launchTrayForActiveSession must be skipped while the tray is hidden")
	}
}
