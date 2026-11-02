//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
)

// Tray-icon visibility. The server decides (per agent, else fleet-wide) and sends the result in every heartbeat
// response as policy.hideTrayIcon; the heartbeat path calls applyTrayPolicy with it.
//
// While hidden the service neither launches the tray (launchTrayForActiveSession) nor lets the watchdog bring it
// back (watchTray), and it stops a tray that is already running. The state is also kept in a marker file under
// %ProgramData%\BASAgent so a service restart or reboot comes up hidden immediately instead of showing the icon
// until the first heartbeat answers. Server unreachable = no new policy = the last applied state stands.

// trayHidden is the agent's current tray visibility. Read by the launch path and the watchdog.
var trayHidden atomic.Bool

// trayHiddenMarkerPath is a variable so tests can point it at a temp directory.
var trayHiddenMarkerPath = func() string {
	return filepath.Join(os.Getenv("ProgramData"), "BASAgent", "tray.hidden")
}

// trayStartFunc and trayStopFunc are variables so tests can observe transitions without a real session.
var (
	trayStartFunc = launchTrayForActiveSession
	trayStopFunc  = stopTrayForActiveSession
)

// loadTrayHidden restores the persisted state. Call once at service start, before the first tray launch.
func loadTrayHidden() {
	_, err := os.Stat(trayHiddenMarkerPath())
	trayHidden.Store(err == nil)
}

// persistTrayHidden records the state: marker present = hidden.
func persistTrayHidden(hide bool) error {
	p := trayHiddenMarkerPath()
	if !hide {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte("hidden by server policy\n"), 0o644)
}

// applyTrayPolicy moves the tray to the requested visibility. It is called on every heartbeat, so repeating the
// state the agent is already in does nothing.
func applyTrayPolicy(hide bool) {
	if trayHidden.Load() == hide {
		return
	}
	// Set the flag first: the watchdog runs on its own timer and must not relaunch a tray we are about to stop.
	trayHidden.Store(hide)
	if err := persistTrayHidden(hide); err != nil {
		log.Printf("[svc] tray visibility: could not persist state (in effect until restart): %v", err)
	}
	if hide {
		log.Printf("[svc] tray icon hidden by server policy")
		trayStopFunc()
		return
	}
	log.Printf("[svc] tray icon shown by server policy")
	trayStartFunc()
}
