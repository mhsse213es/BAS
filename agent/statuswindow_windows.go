//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/rodrigocfd/windigo/ui"
	"golang.org/x/sys/windows"

	"audspect/agent/statusclient"
)

// runStatusWindow opens the agent's status console as a native Win32
// window (windigoWindow, below) instead of the browser. Invoked via
// `bas_agent.exe --status-window`. Falls back to browserWindow if native
// window creation fails.
//
// This used to open the console in the user's default browser, and before
// that in an embedded WebView2 window (abandoned -- WebView2 hosted via the
// service's CreateProcessAsUser/WTSQueryUserToken launch chain reliably
// created the host window but left it permanently invisible, a documented
// Microsoft limitation: https://github.com/MicrosoftEdge/WebView2Feedback/issues/4850).
func runStatusWindow() {
	token := readAPIToken()
	client := statusclient.New(statusclient.DefaultAddr, token)

	win := newWindigoWindow()
	controller := NewStatusController(client, win)
	win.controller = controller

	go controller.Run()
	defer controller.Stop()

	if err := win.Show(); err != nil {
		log.Printf("[status-window] native window failed, falling back to browser: %v", err)
		controller.Stop()
		fallback := newBrowserWindow(token)
		fallback.Show()
	}
}

// readAPIToken reads the local API token written by the service.
func readAPIToken() string {
	path := filepath.Join(os.Getenv("ProgramData"), "BASAgent", "api.token")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func openInBrowser(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(url)
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shell32.NewProc("ShellExecuteW").Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 5 /*SW_SHOW*/)
}

func revealInExplorer(path string) {
	cmd := exec.Command("explorer.exe", "/select,"+path)
	_ = cmd.Start()
}

// windigoWindow implements StatusWindow as a real native Win32 window
// (github.com/rodrigocfd/windigo -- pure Go, zero CGo). Pure presentation:
// it never calls statusclient or agent business logic itself -- every
// button handler forwards to controller (set by runStatusWindow right
// after construction, since StatusController's own constructor needs a
// StatusWindow reference, creating the chicken-and-egg this two-step
// wiring resolves).
type windigoWindow struct {
	wnd        *ui.Main
	controller *StatusController

	lastServerURL string

	lblHeroTitle     *ui.Static
	lblConnServer    *ui.Static
	lblConnLink      *ui.Static
	lblConnState     *ui.Static
	lblConnUptime    *ui.Static
	lblConnHeartbeat *ui.Static

	lblOpTitle  *ui.Static
	lblOpMeta   *ui.Static
	progOp      *ui.ProgressBar
	lblOpResult *ui.Static
}

func newWindigoWindow() *windigoWindow {
	sw := &windigoWindow{}

	cx, cy := ui.Dpi(720, 640)
	sw.wnd = ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent").
			Size(cx, cy),
	)

	sw.lblHeroTitle = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Connecting...").Position(dpiPos(16, 16)).Size(dpiPos(680, 24)))

	sw.lblConnServer = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Server: —").Position(dpiPos(16, 56)).Size(dpiPos(360, 20)))
	sw.lblConnLink = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Link: —").Position(dpiPos(16, 80)).Size(dpiPos(360, 20)))
	sw.lblConnState = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Lifecycle State: —").Position(dpiPos(16, 104)).Size(dpiPos(360, 20)))
	sw.lblConnUptime = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Uptime: —").Position(dpiPos(16, 128)).Size(dpiPos(360, 20)))
	sw.lblConnHeartbeat = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Last Heartbeat: —").Position(dpiPos(16, 152)).Size(dpiPos(360, 20)))

	sw.lblOpTitle = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("No active simulation").Position(dpiPos(400, 56)).Size(dpiPos(300, 20)))
	sw.lblOpMeta = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Awaiting tasking from the BAS console").Position(dpiPos(400, 80)).Size(dpiPos(300, 20)))
	progX, progY := dpiPos(400, 104)
	progCx, progCy := dpiPos(300, 16)
	sw.progOp = ui.NewProgressBar(sw.wnd, ui.OptsProgressBar().
		Position(progX, progY).Size(progCx, progCy))
	sw.progOp.SetRange(0, 100)
	sw.lblOpResult = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("").Position(dpiPos(400, 128)).Size(dpiPos(300, 20)))

	return sw
}

// dpiPos is a small local wrapper around ui.Dpi so every Position/Size call
// site in this file can pass a single (x,y) pair without repeating the
// two-return-value ui.Dpi(x,y) call inline everywhere.
func dpiPos(x, y int) (int, int) { return ui.Dpi(x, y) }

func (sw *windigoWindow) Show() error {
	sw.wnd.RunAsMain()
	return nil
}

func (sw *windigoWindow) Close() {
	_ = sw.wnd.Hwnd().DestroyWindow()
}

// Refresh is called by StatusController from its own polling goroutine,
// never the UI thread. Win32 controls may only be touched from the thread
// that owns the message loop (RunAsMain), so this marshals the actual
// rendering onto that thread via windigo's UiThread instead of calling
// control setters directly here.
func (sw *windigoWindow) Refresh(snap StatusSnapshot) {
	sw.wnd.UiThread(func() { sw.render(snap) })
}

// render performs the actual control updates. Always runs on the UI
// thread (see Refresh). This task wires the hero banner and Connection
// panel; Tasks 5-7 extend this same method (each quoting the prior task's
// closing lines as its own "replace" target) for the remaining panels.
func (sw *windigoWindow) render(snap StatusSnapshot) {
	if !snap.Online {
		sw.lblHeroTitle.SetTextAndResize("Agent service not reachable")
		sw.lblConnLink.SetTextAndResize("Link: Offline")
		return
	}
	s := snap.Status
	sw.lastServerURL = s.ServerURL

	sw.lblConnServer.SetTextAndResize("Server: " + s.ServerURL)
	switch {
	case s.ServerConnected:
		sw.lblConnLink.SetTextAndResize("Link: Connected")
	case s.Paused:
		sw.lblConnLink.SetTextAndResize("Link: Paused (server unreachable, run continues locally)")
	default:
		sw.lblConnLink.SetTextAndResize("Link: Disconnected")
	}
	sw.lblConnState.SetTextAndResize("Lifecycle State: " + orDash(s.State))
	sw.lblConnUptime.SetTextAndResize("Uptime: " + formatUptime(s.UptimeSec))
	if s.LastHeartbeat != nil {
		sw.lblConnHeartbeat.SetTextAndResize("Last Heartbeat: " + s.LastHeartbeat.Format("15:04:05"))
	} else {
		sw.lblConnHeartbeat.SetTextAndResize("Last Heartbeat: —")
	}

	title := "Audspect BAS Agent — " + s.Hostname
	switch {
	case !s.ServerConnected && s.Paused:
		title += "  [PAUSED — SERVER LINK LOST]"
	case !s.ServerConnected:
		title += "  [DISCONNECTED]"
	case s.State == "quarantined":
		title += "  [QUARANTINED]"
	case s.State == "restricted":
		title += "  [RESTRICTED]"
	default:
		title += "  [OK]  v" + s.AgentVersion
	}
	sw.lblHeroTitle.SetTextAndResize(title)
	sw.renderOperation(snap.Activity)
}

// renderOperation updates the Current Operation panel.
func (sw *windigoWindow) renderOperation(a statusclient.ActivityResponse) {
	if a.CurrentOperation != nil && a.CurrentOperation.Running {
		op := a.CurrentOperation
		title := op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		sw.lblOpTitle.SetTextAndResize(title)
		sw.lblOpMeta.SetTextAndResize(fmt.Sprintf("%d steps · phase: %s", op.TotalSteps, orDash(op.Phase)))
		sw.progOp.SetPos(op.Progress)
		sw.lblOpResult.SetTextAndResize("")
		return
	}
	if a.LastOperation != nil {
		op := a.LastOperation
		title := op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		sw.lblOpTitle.SetTextAndResize(title)
		sw.lblOpMeta.SetTextAndResize(fmt.Sprintf("Completed · %ds", op.DurationSec))
		sw.progOp.SetPos(100)
		if op.Result != "" {
			sw.lblOpResult.SetTextAndResize("Result: " + op.Result)
		}
		return
	}
	sw.lblOpTitle.SetTextAndResize("No active simulation")
	sw.lblOpMeta.SetTextAndResize("Awaiting tasking from the BAS console")
	sw.progOp.SetPos(0)
	sw.lblOpResult.SetTextAndResize("")
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func formatUptime(sec int) string {
	h := sec / 3600
	m := (sec % 3600) / 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm %ds", m, sec%60)
}
