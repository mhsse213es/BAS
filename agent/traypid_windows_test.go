//go:build windows

package main

import "testing"

// TestShouldSkipTrayLaunch pins Important finding #7 from the review:
// launchTrayForActiveSession runs on every session logon/connect event
// (service.go), and previously stored the newly-spawned process's PID
// into trayPID unconditionally -- even when that new process was a
// redundant launch destined to self-exit via its own singleton check
// (trayAlreadyRunning, tray_windows.go), racing the STILL-RUNNING real
// tray's PID out of trayPID. Every subsequent Settings/Troubleshoot
// child spawned by that still-running tray would then fail the pipe's
// parent-PID check against the now-wrong value. shouldSkipTrayLaunch is
// the guard that avoids the redundant launch (and therefore the race)
// entirely when the previously recorded tray is still alive.
func TestShouldSkipTrayLaunch(t *testing.T) {
	origAlive := trayProcessAlive
	defer func() { trayProcessAlive = origAlive }()
	defer trayPID.Store(trayPID.Load())

	t.Run("skips when the recorded tray PID is still alive", func(t *testing.T) {
		trayPID.Store(1234)
		trayProcessAlive = func(pid int32) bool { return pid == 1234 }
		if !shouldSkipTrayLaunch() {
			t.Fatal("expected skip == true")
		}
	})

	t.Run("does not skip when the recorded tray PID is no longer alive", func(t *testing.T) {
		trayPID.Store(1234)
		trayProcessAlive = func(pid int32) bool { return false }
		if shouldSkipTrayLaunch() {
			t.Fatal("expected skip == false")
		}
	})

	t.Run("does not skip when no tray has ever been recorded", func(t *testing.T) {
		trayPID.Store(0)
		trayProcessAlive = func(pid int32) bool { return pid != 0 }
		if shouldSkipTrayLaunch() {
			t.Fatal("expected skip == false for an unset trayPID")
		}
	})
}
