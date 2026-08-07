//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

	// Security Controls
	lblCtrlDefender  *ui.Static
	lblCtrlSysmon    *ui.Static
	lblCtrlFirewall  *ui.Static
	lblCtrlAppLocker *ui.Static
	lblCtrlWDAC      *ui.Static
	lblCtrlAMSI      *ui.Static

	// Evidence tiles
	lblEvEvents   *ui.Static
	lblEvDefender *ui.Static
	lblEvSysmon   *ui.Static
	lblEvQueue    *ui.Static

	// Self-Protection rows
	lblSpService *ui.Static
	lblSpPolicy  *ui.Static
	lblSpQueue   *ui.Static
	lblSpUpload  *ui.Static
	lblSpContact *ui.Static

	// Resources
	lblResRam     *ui.Static
	lblResVersion *ui.Static
	lblResId      *ui.Static

	listActivity            *ui.ListView
	btnExport               *ui.Button
	btnDashboard            *ui.Button
	lastActivityFingerprint string
}

func newWindigoWindow() *windigoWindow {
	sw := &windigoWindow{}

	cx, cy := ui.Dpi(920, 640)
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

	// Security Controls
	sw.lblCtrlDefender = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Defender RTP: —").Position(dpiPos(16, 184)).Size(dpiPos(340, 20)))
	sw.lblCtrlSysmon = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Sysmon: —").Position(dpiPos(16, 208)).Size(dpiPos(340, 20)))
	sw.lblCtrlFirewall = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Firewall: —").Position(dpiPos(16, 232)).Size(dpiPos(340, 20)))
	sw.lblCtrlAppLocker = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("AppLocker: —").Position(dpiPos(16, 256)).Size(dpiPos(340, 20)))
	sw.lblCtrlWDAC = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("WDAC: —").Position(dpiPos(16, 280)).Size(dpiPos(340, 20)))
	sw.lblCtrlAMSI = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("AMSI: —").Position(dpiPos(16, 304)).Size(dpiPos(340, 20)))

	// Evidence
	sw.lblEvEvents = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Events Collected: —").Position(dpiPos(400, 184)).Size(dpiPos(300, 20)))
	sw.lblEvDefender = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Defender Alerts: —").Position(dpiPos(400, 208)).Size(dpiPos(300, 20)))
	sw.lblEvSysmon = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Sysmon Detections: —").Position(dpiPos(400, 232)).Size(dpiPos(300, 20)))
	sw.lblEvQueue = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Upload Queue: —").Position(dpiPos(400, 256)).Size(dpiPos(300, 20)))

	// Self-Protection
	sw.lblSpService = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Service Running: —").Position(dpiPos(400, 288)).Size(dpiPos(300, 20)))
	sw.lblSpPolicy = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Policy Sync: —").Position(dpiPos(400, 312)).Size(dpiPos(300, 20)))
	sw.lblSpQueue = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Evidence Queue: —").Position(dpiPos(400, 336)).Size(dpiPos(300, 20)))
	sw.lblSpUpload = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Last Upload OK: —").Position(dpiPos(400, 360)).Size(dpiPos(300, 20)))
	sw.lblSpContact = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Server Contact: —").Position(dpiPos(400, 384)).Size(dpiPos(300, 20)))

	// Resources
	sw.lblResRam = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Memory: —").Position(dpiPos(16, 336)).Size(dpiPos(340, 20)))
	sw.lblResVersion = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Agent Version: —").Position(dpiPos(16, 360)).Size(dpiPos(340, 20)))
	sw.lblResId = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Agent ID: —").Position(dpiPos(16, 384)).Size(dpiPos(340, 20)))

	listX, listY := dpiPos(16, 416)
	listCx, listCy := dpiPos(684, 140)
	colTimeW, _ := dpiPos(100, 0)
	colEventW, _ := dpiPos(560, 0)
	sw.listActivity = ui.NewListView(sw.wnd, ui.OptsListView().
		Position(listX, listY).Size(listCx, listCy).
		Column("Time", colTimeW).Column("Event", colEventW))

	btnExportX, btnExportY := dpiPos(16, 568)
	btnExportW, btnExportH := dpiPos(200, 28)
	sw.btnExport = ui.NewButton(sw.wnd, ui.OptsButton().
		Text("Export Diagnostic Bundle").Position(btnExportX, btnExportY).Width(btnExportW).Height(btnExportH))
	btnDashX, btnDashY := dpiPos(232, 568)
	btnDashW, btnDashH := dpiPos(160, 28)
	sw.btnDashboard = ui.NewButton(sw.wnd, ui.OptsButton().
		Text("Open BAS Console").Position(btnDashX, btnDashY).Width(btnDashW).Height(btnDashH))

	sw.btnExport.On().BnClicked(func() {
		if sw.controller != nil {
			sw.controller.ExportDiagnostics()
		}
	})
	sw.btnDashboard.On().BnClicked(func() {
		if sw.controller != nil {
			sw.controller.OpenDashboard(sw.lastServerURL)
		}
	})

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
	sw.renderControls(snap.Controls)
	sw.renderEvidence(snap.Evidence)
	sw.renderSelfProtection(s, snap.Evidence)
	sw.lblResRam.SetTextAndResize(fmt.Sprintf("Memory: %d MB", s.RamMB))
	sw.lblResVersion.SetTextAndResize("Agent Version: v" + s.AgentVersion)
	sw.lblResId.SetTextAndResize("Agent ID: " + s.AgentID)
	sw.renderActivity(snap.Activity.RecentActivity)
}

// renderActivity rebuilds the activity ListView only when its content has
// actually changed since the last render, using a cheap fingerprint (item
// count + newest entry) instead of comparing every row -- most 5s (or 1s,
// mid-assessment) polls see no new activity at all, so this avoids the
// ListView churn a full delete+rebuild on every single tick would
// otherwise cost.
func (sw *windigoWindow) renderActivity(items []statusclient.Activity) {
	fp := activityFingerprint(items)
	if fp == sw.lastActivityFingerprint {
		return
	}
	sw.lastActivityFingerprint = fp

	sw.listActivity.DeleteAllItems()
	if len(items) == 0 {
		sw.listActivity.AddItem("—", "No recent activity recorded.")
		return
	}
	for _, item := range items {
		sw.listActivity.AddItem(item.Time.Format("15:04:05"), item.Event)
	}
}

func activityFingerprint(items []statusclient.Activity) string {
	if len(items) == 0 {
		return "empty"
	}
	newest := items[0]
	return fmt.Sprintf("%d|%s|%s", len(items), newest.Time.Format(time.RFC3339), newest.Event)
}

// renderControls updates the Security Controls panel.
func (sw *windigoWindow) renderControls(c statusclient.ControlsResponse) {
	status := "ABSENT"
	if c.Defender.Present {
		if c.Defender.RTPEnabled {
			status = "ACTIVE"
		} else {
			status = "DEGRADED"
		}
	}
	extra := ""
	if c.Defender.TamperProtected {
		extra = " +Tamper"
	}
	sw.lblCtrlDefender.SetTextAndResize(fmt.Sprintf("Defender RTP: [%s]%s", status, extra))

	setBool := func(lbl *ui.Static, name string, on bool) {
		s := "ABSENT"
		if on {
			s = "ACTIVE"
		}
		lbl.SetTextAndResize(fmt.Sprintf("%s: [%s]", name, s))
	}
	setBool(sw.lblCtrlSysmon, "Sysmon", c.Sysmon.Present)
	setBool(sw.lblCtrlFirewall, "Firewall", c.Firewall.Enabled)
	setBool(sw.lblCtrlAppLocker, "AppLocker", c.AppLocker.Enabled)
	setBool(sw.lblCtrlWDAC, "WDAC", c.WDAC.Enabled)
	setBool(sw.lblCtrlAMSI, "AMSI", c.AMSI.Enabled)
}

// renderEvidence updates the Evidence tiles.
func (sw *windigoWindow) renderEvidence(ev statusclient.EvidenceResponse) {
	sw.lblEvEvents.SetTextAndResize(fmt.Sprintf("Events Collected: %d", ev.EventsCollected))
	sw.lblEvDefender.SetTextAndResize(fmt.Sprintf("Defender Alerts: %d", ev.DefenderAlerts))
	sw.lblEvSysmon.SetTextAndResize(fmt.Sprintf("Sysmon Detections: %d", ev.SysmonDetections))
	sw.lblEvQueue.SetTextAndResize(fmt.Sprintf("Upload Queue: %d", ev.QueueSize))
}

// renderSelfProtection updates the Self-Protection rows.
func (sw *windigoWindow) renderSelfProtection(s statusclient.StatusResponse, ev statusclient.EvidenceResponse) {
	setRow := func(lbl *ui.Static, name string, on bool) {
		status := "CHECK"
		if on {
			status = "HEALTHY"
		}
		lbl.SetTextAndResize(fmt.Sprintf("%s: %s", name, status))
	}
	setRow(sw.lblSpService, "Service Running", s.ServiceRunning)
	setRow(sw.lblSpPolicy, "Policy Sync", s.State == "active" || s.State == "restricted")
	setRow(sw.lblSpQueue, "Evidence Queue", ev.QueueSize < 100)
	setRow(sw.lblSpUpload, "Last Upload OK", s.LastUploadOk)
	setRow(sw.lblSpContact, "Server Contact", s.ServerConnected)
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
