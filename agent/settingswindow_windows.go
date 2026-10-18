//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/rodrigocfd/windigo/ui"

	"audspect/agent/statusclient"
)

// settingsMutateClient is SettingsController's dependency on the named
// pipe's two mutating calls -- an interface so tests fake it instead of
// dialing a real pipe. mutateClient (below) is the real implementation.
type settingsMutateClient interface {
	TestServer(host string) (TestOutcome, string, error)
	SetServer(host string) (bool, string, error)
}

// mutateClient dials the Task 3 named pipe for one request/response round
// trip per call, mirroring how statusclient.Client is used for the
// read-only API (statuswindow_windows.go) -- a new connection per call,
// never a persistent session, matching Task/Save being discrete clicks.
type mutateClient struct{}

func (mutateClient) call(op, host string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, mutatePipeName)
	if err != nil {
		return "", "", fmt.Errorf("connect to agent: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(mutateRequest{Op: op, Host: host}); err != nil {
		return "", "", fmt.Errorf("send request: %w", err)
	}
	var resp mutateResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", "", fmt.Errorf("read response: %w", err)
	}
	return resp.Outcome, resp.Detail, nil
}

func (c mutateClient) TestServer(host string) (TestOutcome, string, error) {
	outcome, detail, err := c.call("test-server", host)
	return TestOutcome(outcome), detail, err
}

func (c mutateClient) SetServer(host string) (bool, string, error) {
	outcome, detail, err := c.call("set-server", host)
	if err != nil {
		return false, "", err
	}
	return outcome == "ok", detail, nil
}

// SettingsController owns the Test/Save button logic, mirroring
// StatusController's shape (client/window separation, Run/Stop lifecycle)
// so it is unit-testable independent of the real windigo window.
type SettingsController struct {
	client      settingsMutateClient
	stop        chan struct{}
	pendingHost string
}

func NewSettingsController(client settingsMutateClient) *SettingsController {
	return &SettingsController{client: client, stop: make(chan struct{})}
}

// Run blocks until Stop is called. Settings has no poll loop (unlike
// StatusController) -- every action is a direct button click -- but
// keeping the same Run/Stop lifecycle shape lets runSettingsWindow use the
// identical `go controller.Run(); defer controller.Stop()` pattern every
// other controller in this codebase uses.
func (c *SettingsController) Run() { <-c.stop }

func (c *SettingsController) Stop() { close(c.stop) }

// Test validates the candidate host before ever reaching the pipe --
// mirroring handleTestServer's own validation so an invalid host never
// costs a round trip, and matches the result the pipe's own validation
// would give if the client-side check were skipped.
func (c *SettingsController) Test(candidateHost string) (TestOutcome, string) {
	if _, err := ValidateCandidateHost(candidateHost); err != nil {
		return TestOutcomeInvalidHost, err.Error()
	}
	outcome, detail, err := c.client.TestServer(candidateHost)
	if err != nil {
		return TestOutcomeHostUnreachable, err.Error()
	}
	return outcome, detail
}

// RequestSave returns a warning the window must show and get the user to
// accept before ConfirmSave is called -- SetServer is never reached by
// RequestSave alone (Review Focus / the design's "It must not report
// success just because the configuration file was written" extends to
// "must not even attempt to write" without this confirmation step).
func (c *SettingsController) RequestSave(candidateHost string) (needsConfirm bool, warning string) {
	c.pendingHost = candidateHost
	return true, "Saving will restart the agent service and may briefly interrupt connectivity. Continue?"
}

// ConfirmSave commits the host RequestSave recorded.
func (c *SettingsController) ConfirmSave() (ok bool, detail string) {
	host := c.pendingHost
	c.pendingHost = ""
	ok, detail, err := c.client.SetServer(host)
	if err != nil {
		return false, err.Error()
	}
	return ok, detail
}

// runSettingsWindow opens the Settings window as a native Win32 window.
// Invoked via `bas_agent.exe --settings-window`.
func runSettingsWindow() {
	runtime.LockOSThread() // see runStatusWindow's doc comment -- same requirement, same reason.

	token := readAPIToken()
	statusCli := statusclient.New(statusclient.DefaultAddr, token)
	current, err := statusCli.Status(context.Background())
	currentHost := ""
	if err == nil {
		currentHost = current.ServerURL
	}

	controller := NewSettingsController(mutateClient{})
	go controller.Run()
	defer controller.Stop()

	if err := showSettingsWindow(currentHost, controller); err != nil {
		log.Printf("[settings-window] native window failed: %v", err)
	}
}

// showSettingsWindow builds and shows the actual windigo controls: a host
// field pre-filled with currentHost, a Test button, a Save button, and a
// result area. Kept separate from runSettingsWindow so the controller
// wiring above is reachable without a live Win32 window in tests.
func showSettingsWindow(currentHost string, controller *SettingsController) error {
	cx, cy := ui.Dpi(480, 220)
	wnd := ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent — Settings").
			Size(cx, cy),
	)

	ex, ey := ui.Dpi(20, 20)
	ew, eh := ui.Dpi(440, 23)
	hostEdit := ui.NewEdit(wnd, ui.OptsEdit().
		Position(ex, ey).
		Width(ew).Height(eh).
		Text(currentHost))

	rx, ry := ui.Dpi(20, 110)
	rw, rh := ui.Dpi(440, 80)
	resultLbl := ui.NewStatic(wnd, ui.OptsStatic().
		Position(rx, ry).
		Size(rw, rh))

	tx, ty := ui.Dpi(20, 55)
	bw, bh := ui.Dpi(100, 28)
	testBtn := ui.NewButton(wnd, ui.OptsButton().
		Text("Test").
		Position(tx, ty).
		Width(bw).Height(bh))

	sx, sy := ui.Dpi(130, 55)
	saveBtn := ui.NewButton(wnd, ui.OptsButton().
		Text("Save").
		Position(sx, sy).
		Width(bw).Height(bh))

	testBtn.On().BnClicked(func() {
		outcome, detail := controller.Test(hostEdit.Text())
		resultLbl.SetTextAndResize(string(outcome) + ": " + detail)
	})

	confirmed := false
	saveBtn.On().BnClicked(func() {
		if !confirmed {
			_, warning := controller.RequestSave(hostEdit.Text())
			resultLbl.SetTextAndResize(warning + " (click Save again to confirm)")
			confirmed = true
			return
		}
		confirmed = false
		ok, detail := controller.ConfirmSave()
		if ok {
			resultLbl.SetTextAndResize("Saved: " + detail)
		} else {
			resultLbl.SetTextAndResize("Not saved: " + detail)
		}
	})

	wnd.RunAsMain()
	return nil
}
