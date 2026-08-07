//go:build windows

// StatusController's ExportDiagnostics/OpenDashboard call
// exportDiagnosticBundle/revealInExplorer/openInBrowser, which today only
// exist on Windows (the whole tray/status-window/export feature has no
// Linux/macOS implementation yet) -- so despite otherwise having zero
// platform-specific code, this file must carry the same build tag.
package main

import (
	"context"
	"time"

	"audspect/agent/statusclient"
)

// pollInterval returns the adaptive polling cadence for the given
// snapshot: fast while an assessment is actively running, so the progress
// bar feels responsive, settling back to a slower idle cadence otherwise.
func pollInterval(s StatusSnapshot) time.Duration {
	if s.Activity.CurrentOperation != nil && s.Activity.CurrentOperation.Running {
		return 1 * time.Second
	}
	return 5 * time.Second
}

// StatusController owns the poll loop and every user-triggered action.
// StatusWindow implementations only render (Refresh) and forward button
// clicks here -- they never call statusclient or agent business logic
// (exportDiagnosticBundle, openInBrowser) themselves. This keeps
// presentation code free of both networking and side effects, and means a
// future second StatusWindow implementation gets identical polling/action
// behavior for free.
type StatusController struct {
	client *statusclient.Client
	window StatusWindow
	stop   chan struct{}
}

func NewStatusController(client *statusclient.Client, window StatusWindow) *StatusController {
	return &StatusController{client: client, window: window, stop: make(chan struct{})}
}

// Run polls in a loop with an adaptive interval (see pollInterval),
// refreshing the window after every cycle, until Stop is called. Meant to
// be run in its own goroutine.
func (c *StatusController) Run() {
	for {
		snap := c.poll()
		c.window.Refresh(snap)
		select {
		case <-time.After(pollInterval(snap)):
		case <-c.stop:
			return
		}
	}
}

// Stop ends the poll loop. Safe to call once; a second call panics on the
// closed channel by design -- StatusController has exactly one owner
// (runStatusWindow) and is not meant to be stopped from multiple places.
func (c *StatusController) Stop() { close(c.stop) }

func (c *StatusController) poll() StatusSnapshot {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return c.pollWithContext(ctx)
}

// pollWithContext is poll's real body, taking an explicit context so tests
// can control the timeout without waiting for the production default.
func (c *StatusController) pollWithContext(ctx context.Context) StatusSnapshot {
	status, err := c.client.Status(ctx)
	if err != nil {
		return StatusSnapshot{Online: false}
	}
	activity, _ := c.client.Activity(ctx)
	evidence, _ := c.client.Evidence(ctx)
	controls, _ := c.client.Controls(ctx)
	return StatusSnapshot{
		Online:   true,
		Status:   status,
		Activity: activity,
		Evidence: evidence,
		Controls: controls,
	}
}

// ExportDiagnostics runs the existing export flow and reveals the result
// in Explorer. Called by a StatusWindow implementation's Export button
// handler -- see StatusWindow's doc comment for why the window itself
// never calls exportDiagnosticBundle directly.
func (c *StatusController) ExportDiagnostics() {
	if path, err := exportDiagnosticBundle(); err == nil {
		revealInExplorer(path)
	}
}

// OpenDashboard opens the full BAS web console for the given server URL
// (the most recently known value from a StatusSnapshot.Status.ServerURL).
// A no-op if serverURL is empty (not yet known).
func (c *StatusController) OpenDashboard(serverURL string) {
	if serverURL != "" {
		openInBrowser(serverURL)
	}
}
