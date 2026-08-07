package main

import "audspect/agent/statusclient"

// StatusSnapshot is the fully-resolved view of the agent's current status,
// combining all four statusclient endpoints into one value passed to
// StatusWindow.Refresh in a single call. Online is false when the local
// API was unreachable this poll cycle -- implementations show an offline
// state instead of rendering stale field values in that case.
type StatusSnapshot struct {
	Online   bool
	Status   statusclient.StatusResponse
	Activity statusclient.ActivityResponse
	Evidence statusclient.EvidenceResponse
	Controls statusclient.ControlsResponse
}

// StatusWindow is the platform-agnostic contract for the agent's local
// status console. windigoWindow (statuswindow_windows.go) is the native
// Windows implementation; browserWindow (browserwindow_windows.go) is the
// fallback used when native window creation fails. A future Linux/macOS
// agent adds gtkWindow/cocoaWindow here without changing StatusController
// or runStatusWindow.
//
// Implementations are pure presentation -- they render whatever Refresh
// hands them and forward user actions to a StatusController (see
// StatusController's doc comment for why business logic never lives here).
type StatusWindow interface {
	// Show displays the window and blocks for its lifetime. Returns an
	// error only if window creation itself fails (e.g. the native toolkit
	// errors) -- callers fall back to a different StatusWindow
	// implementation in that case, not on a later Refresh call, which
	// cannot itself fail this way.
	Show() error
	// Close requests the window close, unblocking a pending Show call.
	Close()
	// Refresh updates the window's displayed content from a new snapshot.
	// Called by StatusController after every poll and after every action.
	Refresh(StatusSnapshot)
}
