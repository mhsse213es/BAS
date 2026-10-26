//go:build windows

package main

import (
	"log"
	"sync/atomic"
	"time"
)

// The tray icon lives in a process the service starts inside the user's session. Nothing used to
// start it again if that process exited (crash, "End task", the user's profile being reloaded), so
// the icon stayed gone until the next logon. The service now checks on it periodically.

const (
	// trayWatchInterval is how often the service checks that the tray process is still running.
	trayWatchInterval = 30 * time.Second
	// trayProbeWindow is how long a freshly started tray must stay alive to count as the real tray.
	// A second instance in a session that already has a tray (for example one started from the
	// HKLM Run key) exits at once on its own singleton check.
	trayProbeWindow = 2 * time.Second
	// trayDuplicateBackoff is how long the watchdog stays quiet after it found that a tray it did not
	// start is already running, so it does not start a doomed duplicate every interval.
	trayDuplicateBackoff = 10 * time.Minute
)

// trayRetryAfter is the earliest time (unix nanoseconds) the watchdog may start another tray.
var trayRetryAfter atomic.Int64

// shouldRelaunchTray reports whether the watchdog should start a tray now: the tracked tray is not
// running and the duplicate back-off has expired.
func shouldRelaunchTray(now, retryAfter time.Time, trackedAlive bool) bool {
	return !trackedAlive && !now.Before(retryAfter)
}

// noteTrayDuplicate records that a tray the service did not start is already running.
func noteTrayDuplicate(now time.Time) {
	trayRetryAfter.Store(now.Add(trayDuplicateBackoff).UnixNano())
}

// watchTray is called on a timer from the service loop.
func watchTray() {
	now := time.Now()
	if !shouldRelaunchTray(now, time.Unix(0, trayRetryAfter.Load()), trayProcessAlive(trayPID.Load())) {
		return
	}
	tok, ok := activeUserToken()
	if !ok {
		return // nobody is signed in: there is no session to show an icon in
	}
	tok.Close()
	log.Printf("[svc] tray process is not running; starting it in the active session")
	launchTrayForActiveSession()
}
