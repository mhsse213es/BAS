//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/rodrigocfd/windigo/ui"

	"audspect/agent/statusclient"
)

// CheckStatus is one DiagnosticCheck's result.
type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckWarn    CheckStatus = "warn"
	CheckPending CheckStatus = "pending"
)

// ActionButton is a check's optional, context-appropriate remediation
// affordance (e.g. "Test Connection", "Change Server...", "Open Windows
// Date & Time Settings").
type ActionButton struct {
	Label  string
	Action func()
}

// DiagnosticCheck is one row of the Troubleshoot window.
type DiagnosticCheck struct {
	Name         string
	Status       CheckStatus
	Cause        string
	Evidence     string
	Action       string
	ActionButton *ActionButton
}

// diagnosticsDeps are the six checks' dependencies, as function fields so
// tests fake each independently instead of hitting a real service/pipe/
// network. Every field is called fresh by whichever check needs it, never
// memoized here -- see RunDiagnosticCheck's own doc comment for why.
type diagnosticsDeps struct {
	queryServiceRunning func() (bool, error)
	getStatus           func() (statusclient.StatusResponse, error)
	testConnection      func(host string) (TestOutcome, string, time.Time, error)
	getLastConnError    func() *LastConnError
}

// RunDiagnostics runs all six checks in order.
func RunDiagnostics(deps diagnosticsDeps) []DiagnosticCheck {
	checks := make([]DiagnosticCheck, 6)
	for n := 1; n <= 6; n++ {
		checks[n-1] = RunDiagnosticCheck(n, deps)
	}
	return checks
}

// RunDiagnosticCheck runs exactly one of the six checks (1-indexed,
// matching the Troubleshoot window's row numbers), calling deps fresh
// every time -- a per-row "Retry" click must reflect the live result,
// never a cached value from an earlier RunDiagnostics/RunDiagnosticCheck
// call or from a different window's Settings Test click.
func RunDiagnosticCheck(n int, deps diagnosticsDeps) DiagnosticCheck {
	switch n {
	case 1:
		return checkServiceRunning(deps)
	case 2:
		return checkEffectiveConfig(deps)
	case 3:
		return checkConnection(deps)
	case 4:
		return checkClockSkew(deps)
	case 5:
		return checkLastConnError(deps)
	case 6:
		return checkCategorizedCause(deps)
	default:
		return DiagnosticCheck{Name: "Unknown check", Status: CheckPending}
	}
}

func checkServiceRunning(deps diagnosticsDeps) DiagnosticCheck {
	running, err := deps.queryServiceRunning()
	if err != nil {
		return DiagnosticCheck{Name: "Service running", Status: CheckFail, Cause: err.Error()}
	}
	if !running {
		return DiagnosticCheck{
			Name:   "Service running",
			Status: CheckFail,
			Cause:  "The Audspect BAS Agent service is not running.",
			Action: "Start the service",
			ActionButton: &ActionButton{Label: "Start Service", Action: func() {
				if out, err := exec.Command("sc", "start", svcName).CombinedOutput(); err != nil {
					log.Printf("[troubleshoot] start service: %v: %s", err, out)
				}
			}},
		}
	}
	return DiagnosticCheck{Name: "Service running", Status: CheckPass}
}

// checkEffectiveConfig reads StatusResponse.ServerURL directly -- the
// service's own effective config -- never a Settings window's unsaved
// text field, so this always reflects what the agent is actually using.
func checkEffectiveConfig(deps diagnosticsDeps) DiagnosticCheck {
	status, err := deps.getStatus()
	if err != nil {
		return DiagnosticCheck{Name: "Configured server", Status: CheckFail, Cause: "could not read the agent's local status API: " + err.Error()}
	}
	return DiagnosticCheck{Name: "Configured server", Status: CheckPass, Evidence: status.ServerURL}
}

func checkConnection(deps diagnosticsDeps) DiagnosticCheck {
	status, err := deps.getStatus()
	if err != nil {
		return DiagnosticCheck{Name: "Connection test", Status: CheckFail, Cause: "could not read the configured host: " + err.Error()}
	}
	outcome, detail, _, err := deps.testConnection(status.ServerURL)
	if err != nil {
		return DiagnosticCheck{Name: "Connection test", Status: CheckFail, Cause: err.Error()}
	}
	if outcome == TestOutcomeConnected {
		return DiagnosticCheck{Name: "Connection test", Status: CheckPass, Evidence: detail}
	}
	return DiagnosticCheck{
		Name:   "Connection test",
		Status: CheckFail,
		Cause:  detail,
		Action: "Change the server host",
		ActionButton: &ActionButton{Label: "Change Server...", Action: func() {
			openSettingsWindow()
		}},
	}
}

// checkClockSkew measures skew from the same testConnection call checkConnection
// uses, run again here as its own independent request (not a shared/cached
// value from check 3) so this row's own "Retry" always reflects a fresh
// measurement.
func checkClockSkew(deps diagnosticsDeps) DiagnosticCheck {
	status, err := deps.getStatus()
	if err != nil {
		return DiagnosticCheck{Name: "Clock skew", Status: CheckFail, Cause: err.Error()}
	}
	_, _, serverTime, err := deps.testConnection(status.ServerURL)
	if err != nil || serverTime.IsZero() {
		return DiagnosticCheck{Name: "Clock skew", Status: CheckPending, Cause: "could not measure -- the connection test did not return a server timestamp"}
	}
	skew := time.Since(serverTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > 5*time.Minute {
		return DiagnosticCheck{
			Name:     "Clock skew",
			Status:   CheckWarn,
			Cause:    "This machine's clock differs from the server's by more than 5 minutes, which breaks JWT validation.",
			Evidence: fmt.Sprintf("Measured skew: %s", skew.Round(time.Second)),
			Action:   "Fix the system clock",
			ActionButton: &ActionButton{Label: "Open Windows Date & Time Settings", Action: func() {
				_ = exec.Command("control.exe", "/name", "Microsoft.DateAndTime").Start()
			}},
		}
	}
	return DiagnosticCheck{Name: "Clock skew", Status: CheckPass, Evidence: fmt.Sprintf("Measured skew: %s", skew.Round(time.Second))}
}

func checkLastConnError(deps diagnosticsDeps) DiagnosticCheck {
	lce := deps.getLastConnError()
	if lce == nil || lce.Category == ConnErrorNone {
		return DiagnosticCheck{Name: "Last connection error", Status: CheckPass, Evidence: "No recorded connection failures."}
	}
	return DiagnosticCheck{
		Name:     "Last connection error",
		Status:   CheckWarn,
		Cause:    lce.Detail,
		Evidence: fmt.Sprintf("Category: %s, at %s", lce.Category, lce.At.Format(time.RFC3339)),
	}
}

// checkCategorizedCause labels check 5's evidence against the runbook's
// known categories -- only claiming a specific cause (proxy auth, DNS,
// TCP, TLS, server-side rejection) when lce.Category actually says so,
// never as a default guess.
func checkCategorizedCause(deps diagnosticsDeps) DiagnosticCheck {
	lce := deps.getLastConnError()
	if lce == nil || lce.Category == ConnErrorNone {
		return DiagnosticCheck{Name: "Likely cause", Status: CheckPass, Evidence: "No failure to categorize."}
	}
	switch lce.Category {
	case ConnErrorProxyAuth:
		return DiagnosticCheck{Name: "Likely cause", Status: CheckWarn, Cause: "Proxy authentication is likely blocking the connection.", Evidence: lce.Detail}
	case ConnErrorDNS:
		return DiagnosticCheck{Name: "Likely cause", Status: CheckWarn, Cause: "DNS resolution is failing for the configured host.", Evidence: lce.Detail}
	case ConnErrorTCP:
		return DiagnosticCheck{Name: "Likely cause", Status: CheckWarn, Cause: "The host is unreachable at the network level (firewall or routing).", Evidence: lce.Detail}
	case ConnErrorTLS:
		return DiagnosticCheck{Name: "Likely cause", Status: CheckWarn, Cause: "TLS certificate validation is failing.", Evidence: lce.Detail}
	case ConnErrorServerRejected:
		return DiagnosticCheck{Name: "Likely cause", Status: CheckWarn, Cause: "The server is rejecting requests -- check the configured AGENT_SECRET.", Evidence: lce.Detail}
	default:
		return DiagnosticCheck{Name: "Likely cause", Status: CheckWarn, Cause: "Unclassified connection failure.", Evidence: lce.Detail}
	}
}

// captureServerTime makes an unauthenticated request to host purely to
// read the standard Date response header for clock-skew measurement. TLS
// verification is intentionally skipped here: this request never sends a
// secret and never trusts the response body or the peer's identity --
// only a timestamp header -- so it doesn't weaken checkConnection's real
// test, which goes through the pipe and performs full certificate
// validation.
func captureServerTime(host string) time.Time {
	u, err := url.Parse(host)
	if err != nil {
		return time.Time{}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(u.Scheme + "://" + u.Host + "/")
	if err != nil {
		return time.Time{}
	}
	defer resp.Body.Close()
	t, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return time.Time{}
	}
	return t
}

// testConnectionReal is diagnosticsDeps.testConnection's production
// implementation: the real outcome/detail come from the same named-pipe
// "test-server" call Settings uses (mutateClient, settingswindow_windows.go)
// against the currently configured host, never a candidate; the server
// timestamp comes from a separate, unauthenticated request purely for the
// clock-skew signal.
func testConnectionReal(host string) (TestOutcome, string, time.Time, error) {
	outcome, detail, err := (mutateClient{}).TestServer(host)
	if err != nil {
		return TestOutcomeHostUnreachable, err.Error(), time.Time{}, err
	}
	var serverTime time.Time
	if outcome == TestOutcomeConnected {
		serverTime = captureServerTime(host)
	}
	return outcome, detail, serverTime, nil
}

// realDiagnosticsDeps wires every check to its real, production source.
func realDiagnosticsDeps(client *statusclient.Client) diagnosticsDeps {
	return diagnosticsDeps{
		queryServiceRunning: func() (bool, error) { return svcRunning(svcName), nil },
		getStatus: func() (statusclient.StatusResponse, error) {
			return client.Status(context.Background())
		},
		testConnection: testConnectionReal,
		getLastConnError: func() *LastConnError {
			status, err := client.Status(context.Background())
			if err != nil || status.LastConnError == nil {
				return nil
			}
			return &LastConnError{
				Category: ConnErrorCategory(status.LastConnError.Category),
				Detail:   status.LastConnError.Detail,
				At:       status.LastConnError.At,
			}
		},
	}
}

// runTroubleshootWindow opens the Troubleshoot window as a native Win32
// window. Invoked via `bas_agent.exe --troubleshoot-window`.
func runTroubleshootWindow() {
	runtime.LockOSThread() // see runStatusWindow's doc comment -- same requirement, same reason.

	token := readAPIToken()
	client := statusclient.New(statusclient.DefaultAddr, token)
	deps := realDiagnosticsDeps(client)

	if err := showTroubleshootWindow(deps); err != nil {
		log.Printf("[troubleshoot-window] native window failed: %v", err)
	}
}

// showTroubleshootWindow builds the six rows, each independently
// re-runnable via its own "Retry" button, plus any ActionButton the
// check's current result offers. "Export Diagnostic Bundle" is the
// escalation fallback already on the tray menu -- unchanged, not
// duplicated here.
func showTroubleshootWindow(deps diagnosticsDeps) error {
	cx, cy := ui.Dpi(560, 420)
	wnd := ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent — Troubleshoot").
			Size(cx, cy),
	)

	type row struct {
		result  *ui.Static
		retry   *ui.Button
		action  *ui.Button
		current *DiagnosticCheck
	}
	rows := make([]*row, 6)

	rowH := 60
	for i := 0; i < 6; i++ {
		y := 20 + i*rowH
		lx, ly := ui.Dpi(20, y)
		lw, lh := ui.Dpi(380, rowH-10)
		resultLbl := ui.NewStatic(wnd, ui.OptsStatic().Position(lx, ly).Size(lw, lh))

		rx, ry := ui.Dpi(410, y)
		rw, rh := ui.Dpi(60, 24)
		retryBtn := ui.NewButton(wnd, ui.OptsButton().Text("Retry").Position(rx, ry).Width(rw).Height(rh))

		ax, ay := ui.Dpi(480, y)
		aw, ah := ui.Dpi(60, 24)
		actionBtn := ui.NewButton(wnd, ui.OptsButton().Text("").Position(ax, ay).Width(aw).Height(ah))

		rows[i] = &row{result: resultLbl, retry: retryBtn, action: actionBtn}
	}

	render := func(n int) {
		check := RunDiagnosticCheck(n+1, deps)
		rows[n].current = &check
		text := fmt.Sprintf("%s: %s", check.Name, check.Status)
		if check.Cause != "" {
			text += "\n" + check.Cause
		}
		if check.Evidence != "" {
			text += "\n" + check.Evidence
		}
		rows[n].result.SetTextAndResize(text)
		if check.ActionButton != nil {
			rows[n].action.SetText(check.ActionButton.Label)
		} else {
			rows[n].action.SetText("")
		}
	}

	for i := range rows {
		n := i
		rows[n].retry.On().BnClicked(func() { render(n) })
		rows[n].action.On().BnClicked(func() {
			if rows[n].current != nil && rows[n].current.ActionButton != nil {
				rows[n].current.ActionButton.Action()
			}
		})
	}

	for i := range rows {
		render(i)
	}

	wnd.RunAsMain()
	return nil
}
