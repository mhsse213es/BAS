//go:build windows

package main

import (
	"errors"
	"testing"
)

// TestStopTrayForActiveSession pins the fix for an upgrade/reinstall over an
// already-installed agent: the service stopping (MSI's ServiceControl Stop)
// never terminated the separately-spawned tray process (same exe, different
// session, not tracked by the SCM), so Windows Installer's Restart Manager
// found it still holding bas_agent.exe open and refused to proceed
// automatically ("unable to automatically close all requested applications").
func TestStopTrayForActiveSession(t *testing.T) {
	origAlive := trayProcessAlive
	origKill := trayKillFunc
	defer func() { trayProcessAlive = origAlive; trayKillFunc = origKill }()

	t.Run("terminates and clears a running tray", func(t *testing.T) {
		trayPID.Store(4242)
		trayProcessAlive = func(pid int32) bool { return pid == 4242 }
		var killed int32
		trayKillFunc = func(pid int32) error { killed = pid; return nil }

		stopTrayForActiveSession()

		if killed != 4242 {
			t.Fatalf("killed pid = %d, want 4242", killed)
		}
		if trayPID.Load() != 0 {
			t.Fatalf("trayPID = %d, want cleared to 0 after a successful stop", trayPID.Load())
		}
	})

	t.Run("no-op when no tray is recorded as alive", func(t *testing.T) {
		trayPID.Store(0)
		trayProcessAlive = func(pid int32) bool { return false }
		called := false
		trayKillFunc = func(pid int32) error { called = true; return nil }

		stopTrayForActiveSession()

		if called {
			t.Fatal("expected trayKillFunc not to be called when no tray is alive")
		}
	})

	t.Run("leaves trayPID set when termination fails", func(t *testing.T) {
		trayPID.Store(99)
		trayProcessAlive = func(pid int32) bool { return pid == 99 }
		trayKillFunc = func(int32) error { return errors.New("access denied") }

		stopTrayForActiveSession()

		if trayPID.Load() != 99 {
			t.Fatalf("trayPID = %d, want unchanged at 99 after a failed kill (never guess success)", trayPID.Load())
		}
	})
}
