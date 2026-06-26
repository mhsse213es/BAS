//go:build windows

package main

import "log"

var procSetThreadExecutionState = modKernel32.NewProc("SetThreadExecutionState")

const (
	esSystemRequired  uintptr = 0x00000001 // prevent system sleep
	esDisplayRequired uintptr = 0x00000002 // prevent display sleep / screensaver
	esContinuous      uintptr = 0x80000000 // hold until explicitly cleared
)

// inhibitScreenTimeout holds a display + system wake lock for the calling
// goroutine via SetThreadExecutionState. The OS will not blank the screen,
// start the screensaver, or sleep the system until restoreScreenTimeout is
// called. The call is best-effort: if it fails the simulation continues.
//
// Called only when the dispatched ScenarioCommand carries PreventScreenTimeout=true,
// which is set exclusively by a scenario YAML author (prevent_screen_timeout: true).
// It is never called globally on agent startup.
func inhibitScreenTimeout() {
	prev, _, _ := procSetThreadExecutionState.Call(esContinuous | esSystemRequired | esDisplayRequired)
	if prev == 0 {
		log.Printf("[power] SetThreadExecutionState inhibit failed — simulation may be interrupted by screensaver/lock")
		return
	}
	log.Printf("[power] screen timeout inhibited for this run (ES_CONTINUOUS|ES_SYSTEM|ES_DISPLAY)")
}

// restoreScreenTimeout clears the wake lock set by inhibitScreenTimeout.
// Always paired with inhibitScreenTimeout via defer; safe to call even if
// inhibitScreenTimeout failed.
func restoreScreenTimeout() {
	procSetThreadExecutionState.Call(esContinuous)
	log.Printf("[power] screen timeout restored — normal power management resumed")
}
