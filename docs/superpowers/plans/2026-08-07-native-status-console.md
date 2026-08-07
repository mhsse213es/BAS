# Native Status Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the agent's browser-based status console with a real native Windows window (no browser, no WebView2), matching how enterprise EDR agents (CrowdStrike/Trellix/TrendMicro) present local status — built with `windigo`, a pure-Go (zero CGo) native Win32 toolkit, consistent with this codebase's existing zero-CGO philosophy already proven in `tray_windows.go`.

**Architecture:** `agent/statuswindow_windows.go`'s `runStatusWindow()` currently calls `openInBrowser()`; it now builds and shows a native `windigo` window instead, invoked identically (`bas_agent.exe --status-window`, spawned by the tray as a separate process — `tray_windows.go` is unchanged). The window polls the **existing, unmodified** local JSON API (`127.0.0.1:9001/status`, `/activity`, `/evidence`, `/controls`) every 5 seconds via `WM_TIMER`, the same cadence and endpoints the old HTML page's JS `tick()` already used — zero backend changes anywhere in this plan. If native window creation fails for any reason, it falls back to `openInBrowser()` against the existing HTML page, which stays in place as the safety net (same "native primary, browser fallback" philosophy this codebase already used for WebView2).

**Content parity note:** "full parity" here means the native window shows every data field the HTML dashboard shows (hero status, connection, current operation, all 6 security controls, evidence, self-protection, resources, activity feed). It does **not** mean pixel-identical gradients/rounded cards/animated pulse dots — those are CSS effects with no native-control equivalent, and matching them isn't actually how real native EDR consoles look anyway. Status is conveyed with native controls and bracketed/prefixed text (e.g. `[ACTIVE]`, `[DEGRADED]`) instead of colored dot glyphs.

**Tech Stack:** Go 1.26 (`agent` module, `//go:build windows`), `github.com/rodrigocfd/windigo` (new dependency — pure Go, zero CGo, wraps native Win32 controls).

## Global Constraints

- Zero backend/API changes — every field this window shows already exists at `/status`, `/activity`, `/evidence`, `/controls` (`agent/local_api_windows.go`, unmodified by this plan).
- No CGo — `windigo` is pure Go over raw syscalls, matching `tray_windows.go`'s existing approach and this module's `go.mod` (currently just `gorilla/websocket` + `golang.org/x/sys`).
- `openStatusWindow()` in `tray_windows.go` (spawns `--status-window` as a separate process) is unchanged — this plan only changes what that separate process does once it starts.
- `ui_dashboard.html` and its `/` route in `local_api_windows.go` are **not deleted** — they become the fallback path if native window creation fails.
- This environment cannot render or screenshot a native Win32 window (no display session, unlike a browser page this session could inspect via Claude-in-Chrome) — every task's verification is "builds cleanly" plus an explicit manual-run note; visually confirming the window looks/behaves correctly on a real Windows machine is the user's job, same as Task 6 of the Verified Agent Uninstall plan's per-OS validation gate earlier this session.
- `windigo`'s exact method names beyond what's been verified below (`ui.NewMain`/`NewStatic`/`NewButton`/`NewProgressBar`/`NewListView`, `Static.SetTextAndResize`/`.Text()`, `ProgressBar.SetPos`/`.SetRange`, `ListView.AddItem`/`.DeleteAllItems()`, `.On().BnClicked(func(){})`, `wnd.RunAsMain()`, `Main.WmTimer(id, func())`) were confirmed via the package's real godoc/README, not memorized — but this is a less common library, so **Task 1's Step 2 runs `go doc` for real against the downloaded module** before any other control-wiring code is written, and every later task's build step is the actual correctness check, not this plan's prose.

---

### Task 1: Add `windigo`, verify its real API, build the window shell + polling skeleton

**Files:**
- Modify: `agent/go.mod`, `agent/go.sum` (add `github.com/rodrigocfd/windigo`)
- Modify: `agent/statuswindow_windows.go` (replace `runStatusWindow`)

**Interfaces:**
- Consumes: `agent/local_api_windows.go`'s existing endpoints (unmodified) — `GET /status`, `/activity`, `/evidence`, `/controls`, all requiring `Authorization: Bearer <token>` (token read from `%ProgramData%\BASAgent\api.token` via the existing `readAPIToken()` in `statuswindow_windows.go`).
- Produces: a `*statusWindow` type with fields for every control later tasks attach to (defined here, populated there) — `wnd *ui.Main`, plus one `*ui.Static` per data field this plan lists, one `*ui.ProgressBar`, one `*ui.ListView`, two `*ui.Button`. Later tasks add fields to this same struct; the exact field list is finalized in Task 5.

- [ ] **Step 1: Add the dependency**

```bash
cd agent
go get github.com/rodrigocfd/windigo@latest
```

Expected: `go.mod`/`go.sum` gain the new module; `go build ./...` still succeeds (nothing references it yet).

- [ ] **Step 2: Verify the real API against the downloaded module**

```bash
go doc github.com/rodrigocfd/windigo/ui Static
go doc github.com/rodrigocfd/windigo/ui ProgressBar
go doc github.com/rodrigocfd/windigo/ui ListView
go doc github.com/rodrigocfd/windigo/ui Main
go doc github.com/rodrigocfd/windigo/ui OptsStatic
go doc github.com/rodrigocfd/windigo/ui OptsButton
go doc github.com/rodrigocfd/windigo/ui OptsProgressBar
go doc github.com/rodrigocfd/windigo/ui OptsListView
```

Confirm `SetTextAndResize`, `SetPos`, `SetRange`, `AddItem`, `DeleteAllItems`, and the options-builder method names (`.Position(x,y)`, `.Size(cx,cy)`, `.Text(s)`) match what this plan uses in every later step. **If any name differs, that's this step catching it early — fix it here in your own notes before proceeding, don't silently carry a wrong name into Task 2+.**

- [ ] **Step 3: Replace `runStatusWindow` with the window shell**

In `agent/statuswindow_windows.go`, replace (currently the full file):

```go
//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runStatusWindow opens the agent's status console in the user's default
// browser, pointed at the agent's local HTTP server. Invoked via
// `bas_agent.exe --status-window`.
//
// This used to host the console in an embedded WebView2 window instead.
// That was abandoned: WebView2 hosted in a process launched via the
// service's CreateProcessAsUser/WTSQueryUserToken chain (exactly this
// agent's tray -> status-window launch path) reliably created the host
// window but left it permanently invisible (IsWindowVisible false from the
// moment of creation, with no error at any layer) -- confirmed via live
// diagnostic logging against the real production launch path, not a
// synthetic reproduction. This is a known, Microsoft-acknowledged
// limitation of WebView2 under a service-launched/impersonated-token
// session process, not something fixable in this codebase:
// https://github.com/MicrosoftEdge/WebView2Feedback/issues/4850
// https://github.com/MicrosoftEdge/WebView2Feedback/issues/2434 (closed by
// Microsoft as "not planned")
// The default browser has no such limitation and needs no embedding at all.
func runStatusWindow() {
	token := readAPIToken()
	url := "http://127.0.0.1:9001/"
	if token != "" {
		url += "?t=" + token
	}
	openInBrowser(url)
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
```

with:

```go
//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/rodrigocfd/windigo/ui"
	"golang.org/x/sys/windows"
)

// runStatusWindow opens the agent's status console as a native Win32
// window (built with windigo -- pure Go, zero CGo, same philosophy as this
// file's tray icon in tray_windows.go). Invoked via
// `bas_agent.exe --status-window`.
//
// This used to open the console in the user's default browser, and before
// that in an embedded WebView2 window (abandoned -- WebView2 hosted via the
// service's CreateProcessAsUser/WTSQueryUserToken launch chain reliably
// created the host window but left it permanently invisible, a documented
// Microsoft limitation: https://github.com/MicrosoftEdge/WebView2Feedback/issues/4850).
// A real native window has no such limitation. If window creation fails
// for any reason, this falls back to the browser -- see
// runStatusWindowNative's error return.
func runStatusWindow() {
	if err := runStatusWindowNative(); err != nil {
		log.Printf("[status-window] native window failed, falling back to browser: %v", err)
		openInBrowserFallback()
	}
}

// openInBrowserFallback opens the existing HTML status page (unmodified --
// see local_api_windows.go's "/" route and ui_dashboard.html) in the
// user's default browser. Used only when native window creation fails.
func openInBrowserFallback() {
	token := readAPIToken()
	url := "http://127.0.0.1:9001/"
	if token != "" {
		url += "?t=" + token
	}
	openInBrowser(url)
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

// statusWindowClient polls the agent's own local HTTP API -- the same
// endpoints and cadence the old HTML page's JS tick() used, just from Go
// instead of fetch(). localAPIAddr and the /status /activity /evidence
// /controls routes are defined in local_api_windows.go, unmodified here.
type statusWindowClient struct {
	token  string
	client *http.Client
}

func newStatusWindowClient() *statusWindowClient {
	return &statusWindowClient{
		token:  readAPIToken(),
		client: &http.Client{Timeout: 4 * time.Second},
	}
}

func (c *statusWindowClient) getJSON(path string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, "http://"+localAPIAddr+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d from %s", resp.StatusCode, path)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// statusWindow holds every control the dashboard needs. Populated across
// Tasks 2-5; this task only wires the shell (title, poll timer, offline
// detection) with a single placeholder Static so the window is visibly
// alive and buildable end to end before the remaining panels are added.
type statusWindow struct {
	wnd    *ui.Main
	client *statusWindowClient

	lblHeroTitle *ui.Static
}

const statusPollInterval = 5 * time.Second

// runStatusWindowNative builds and runs the native window. Returns an
// error if window creation itself fails (e.g. an unexpected Win32 error) --
// runStatusWindow's caller falls back to the browser in that case. Once
// RunAsMain is reached and the window is showing, this function blocks for
// the life of the window and any error after that point cannot usefully
// change the caller's behavior (the window is already visible), so it is
// only logged.
func runStatusWindowNative() error {
	sw := &statusWindow{client: newStatusWindowClient()}

	sw.wnd = ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent").
			Size(ui.Dpi(720, 640)),
	)

	sw.lblHeroTitle = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Connecting...").
		Position(ui.Dpi(16, 16)).
		Size(ui.Dpi(400, 24)))

	sw.wnd.On().WmTimer(1, func() { sw.poll() })

	sw.wnd.On().WmCreate(func(_ ui.WmCreate) int {
		windows.NewLazySystemDLL("user32.dll").NewProc("SetTimer").Call(
			uintptr(sw.wnd.Hwnd()), 1, uintptr(statusPollInterval.Milliseconds()), 0)
		sw.poll()
		return 0
	})

	return nil // window construction itself didn't panic/error; RunAsMain runs the message loop
	// Note: RunAsMain() is called by the caller in Step 4 below, not here --
	// see that step for why runStatusWindowNative's error-return contract
	// only covers construction, not the blocking run loop.
}

// poll fetches /status and updates the fields this task owns. Later tasks
// extend this same function to update their own panels' controls.
func (sw *statusWindow) poll() {
	var s map[string]interface{}
	if err := sw.client.getJSON("/status", &s); err != nil {
		sw.lblHeroTitle.SetTextAndResize("Agent service not reachable")
		return
	}
	hostname, _ := s["hostname"].(string)
	sw.lblHeroTitle.SetTextAndResize("Audspect BAS Agent — " + hostname)
}
```

This step's `runStatusWindowNative` deliberately has a rough edge (a `return nil` before `RunAsMain` with a comment explaining why) — **Step 4 below removes that rough edge**, this is written in two steps on purpose so Step 3's diff is reviewable as "does the shell compile and wire a timer correctly" before Step 4 changes control flow to actually block on the message loop.

- [ ] **Step 4: Fix the control flow so the window actually runs**

Replace (the `return nil` line and its comment from Step 3):

```go
	return nil // window construction itself didn't panic/error; RunAsMain runs the message loop
	// Note: RunAsMain() is called by the caller in Step 4 below, not here --
	// see that step for why runStatusWindowNative's error-return contract
	// only covers construction, not the blocking run loop.
}
```

with:

```go
	sw.wnd.RunAsMain()
	return nil
}
```

- [ ] **Step 5: Build**

```bash
go build ./...
```

Expected: succeeds. This is a Windows-only file (`//go:build windows`) built natively on this Windows dev machine, so this is a real compile, not just a cross-compile syntax check.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum statuswindow_windows.go
git commit -m "$(cat <<'EOF'
feat(agent): native status window shell (windigo), replaces browser console

runStatusWindow now builds a real native Win32 window via windigo
(pure Go, zero CGo, same philosophy as tray_windows.go's existing
native tray icon) instead of opening the console in the default
browser. Falls back to the browser automatically if native window
creation fails. Polls the existing, unmodified local JSON API
(127.0.0.1:9001/status) on a 5s timer -- no backend changes. This
task only wires the shell (title bar, poll loop, one live field);
Tasks 2-5 add the remaining panels.
EOF
)"
git push
```

---

### Task 2: Hero/status banner, Connection panel, offline state

**Files:**
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusWindow` struct and `poll()` from Task 1; `/status` JSON fields (`agentVersion`, `hostname`, `serverUrl`, `serverConnected`, `state`, `uptimeSec`, `lastHeartbeat`, `paused`, `graceSec`, `disconnectedSec`, `ramMB`, `agentId`) — all already served by the unmodified `handleLocalStatus` in `local_api_windows.go`.
- Produces: `statusWindow.setOverallStatus(s map[string]interface{})`, consumed by Task 3-5's `poll()` extensions the same way.

- [ ] **Step 1: Add the Connection panel fields to `statusWindow`**

Add to the `statusWindow` struct (from Task 1):

```go
	lblConnServer    *ui.Static
	lblConnLink      *ui.Static
	lblConnState     *ui.Static
	lblConnUptime    *ui.Static
	lblConnHeartbeat *ui.Static
```

- [ ] **Step 2: Create the controls in `runStatusWindowNative`**

Add after `sw.lblHeroTitle`'s creation:

```go
	sw.lblConnServer = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Server: —").Position(ui.Dpi(16, 56)).Size(ui.Dpi(360, 20)))
	sw.lblConnLink = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Link: —").Position(ui.Dpi(16, 80)).Size(ui.Dpi(360, 20)))
	sw.lblConnState = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Lifecycle State: —").Position(ui.Dpi(16, 104)).Size(ui.Dpi(360, 20)))
	sw.lblConnUptime = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Uptime: —").Position(ui.Dpi(16, 128)).Size(ui.Dpi(360, 20)))
	sw.lblConnHeartbeat = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Last Heartbeat: —").Position(ui.Dpi(16, 152)).Size(ui.Dpi(360, 20)))
```

- [ ] **Step 3: Replace `poll()` with the fuller version**

Replace (Task 1's `poll` function):

```go
func (sw *statusWindow) poll() {
	var s map[string]interface{}
	if err := sw.client.getJSON("/status", &s); err != nil {
		sw.lblHeroTitle.SetTextAndResize("Agent service not reachable")
		return
	}
	hostname, _ := s["hostname"].(string)
	sw.lblHeroTitle.SetTextAndResize("Audspect BAS Agent — " + hostname)
}
```

with:

```go
func (sw *statusWindow) poll() {
	var s map[string]interface{}
	if err := sw.client.getJSON("/status", &s); err != nil {
		sw.setOffline()
		return
	}
	sw.setOverallStatus(s)
}

// setOffline reflects an unreachable local API -- the agent service may be
// starting or stopped. Matches the old HTML page's goOffline().
func (sw *statusWindow) setOffline() {
	sw.lblHeroTitle.SetTextAndResize("Agent service not reachable")
	sw.lblConnLink.SetTextAndResize("Link: Offline")
}

// setOverallStatus renders the hero banner + connection panel from a
// decoded /status response. Later tasks (3-5) extend this same function to
// also render their own panels from the same response plus their own
// endpoint calls, so every panel updates on the same 5s tick.
func (sw *statusWindow) setOverallStatus(s map[string]interface{}) {
	hostname, _ := s["hostname"].(string)
	agentVersion, _ := s["agentVersion"].(string)
	serverURL, _ := s["serverUrl"].(string)
	serverConnected, _ := s["serverConnected"].(bool)
	state, _ := s["state"].(string)
	uptimeSec, _ := s["uptimeSec"].(float64)
	lastHeartbeat, _ := s["lastHeartbeat"].(string)
	paused, _ := s["paused"].(bool)

	sw.lblConnServer.SetTextAndResize("Server: " + serverURL)
	if serverConnected {
		sw.lblConnLink.SetTextAndResize("Link: Connected")
	} else if paused {
		sw.lblConnLink.SetTextAndResize("Link: Paused (server unreachable, run continues locally)")
	} else {
		sw.lblConnLink.SetTextAndResize("Link: Disconnected")
	}
	sw.lblConnState.SetTextAndResize("Lifecycle State: " + orDash(state))
	sw.lblConnUptime.SetTextAndResize("Uptime: " + formatUptime(int(uptimeSec)))
	sw.lblConnHeartbeat.SetTextAndResize("Last Heartbeat: " + orDash(lastHeartbeat))

	title := "Audspect BAS Agent — " + hostname
	switch {
	case !serverConnected && paused:
		title += "  [PAUSED — SERVER LINK LOST]"
	case !serverConnected:
		title += "  [DISCONNECTED]"
	case state == "quarantined":
		title += "  [QUARANTINED]"
	case state == "restricted":
		title += "  [RESTRICTED]"
	default:
		title += "  [OK]  v" + agentVersion
	}
	sw.lblHeroTitle.SetTextAndResize(title)
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
```

- [ ] **Step 4: Build**

```bash
go build ./...
```

Expected: succeeds.

- [ ] **Step 5: Commit**

```bash
git add statuswindow_windows.go
git commit -m "feat(agent): native status window - hero banner + connection panel"
git push
```

---

### Task 3: Current Operation panel

**Files:**
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusWindow.poll()` from Task 2; `/activity` JSON (`currentOperation`, `lastOperation` — each with `scenarioName`, `techniqueId`, `phase`, `progress`, `totalSteps`, `startTime`, `running`, `result`, `completedAt`, `durationSec`), already served unmodified by `handleLocalActivity`.
- Produces: nothing new consumed by later tasks — this panel is self-contained.

- [ ] **Step 1: Add the Current Operation fields to `statusWindow`**

```go
	lblOpTitle  *ui.Static
	lblOpMeta   *ui.Static
	progOp      *ui.ProgressBar
	lblOpResult *ui.Static
```

- [ ] **Step 2: Create the controls**

Add after the Connection panel's controls in `runStatusWindowNative`:

```go
	sw.lblOpTitle = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("No active simulation").Position(ui.Dpi(400, 56)).Size(ui.Dpi(300, 20)))
	sw.lblOpMeta = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Awaiting tasking from the BAS console").Position(ui.Dpi(400, 80)).Size(ui.Dpi(300, 20)))
	sw.progOp = ui.NewProgressBar(sw.wnd, ui.OptsProgressBar().
		Position(ui.Dpi(400, 104)).Size(ui.Dpi(300, 16)))
	sw.progOp.SetRange(0, 100)
	sw.lblOpResult = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("").Position(ui.Dpi(400, 128)).Size(ui.Dpi(300, 20)))
```

- [ ] **Step 3: Extend `setOverallStatus` to also fetch and render `/activity`**

Replace (Task 2's `setOverallStatus`, only its final lines, right before the closing `}`):

```go
	sw.lblHeroTitle.SetTextAndResize(title)
}
```

with:

```go
	sw.lblHeroTitle.SetTextAndResize(title)

	var a map[string]interface{}
	if err := sw.client.getJSON("/activity", &a); err == nil {
		sw.setOperation(a)
	}
}

// setOperation renders the Current Operation panel from a decoded
// /activity response. Matches the old HTML page's renderOperation().
func (sw *statusWindow) setOperation(a map[string]interface{}) {
	if cur, ok := a["currentOperation"].(map[string]interface{}); ok && cur != nil {
		running, _ := cur["running"].(bool)
		if running {
			name, _ := cur["scenarioName"].(string)
			technique, _ := cur["techniqueId"].(string)
			totalSteps, _ := cur["totalSteps"].(float64)
			progress, _ := cur["progress"].(float64)
			phase, _ := cur["phase"].(string)

			title := name
			if technique != "" {
				title = technique + "  " + name
			}
			sw.lblOpTitle.SetTextAndResize(title)
			sw.lblOpMeta.SetTextAndResize(fmt.Sprintf("%d steps · phase: %s", int(totalSteps), orDash(phase)))
			sw.progOp.SetPos(int(progress))
			sw.lblOpResult.SetTextAndResize("")
			return
		}
	}
	if last, ok := a["lastOperation"].(map[string]interface{}); ok && last != nil {
		name, _ := last["scenarioName"].(string)
		technique, _ := last["techniqueId"].(string)
		durationSec, _ := last["durationSec"].(float64)
		result, _ := last["result"].(string)

		title := name
		if technique != "" {
			title = technique + "  " + name
		}
		sw.lblOpTitle.SetTextAndResize(title)
		sw.lblOpMeta.SetTextAndResize(fmt.Sprintf("Completed · %ds", int(durationSec)))
		sw.progOp.SetPos(100)
		if result != "" {
			sw.lblOpResult.SetTextAndResize("Result: " + result)
		}
		return
	}
	sw.lblOpTitle.SetTextAndResize("No active simulation")
	sw.lblOpMeta.SetTextAndResize("Awaiting tasking from the BAS console")
	sw.progOp.SetPos(0)
	sw.lblOpResult.SetTextAndResize("")
}
```

- [ ] **Step 4: Build**

```bash
go build ./...
```

Expected: succeeds.

- [ ] **Step 5: Commit**

```bash
git add statuswindow_windows.go
git commit -m "feat(agent): native status window - current operation panel"
git push
```

---

### Task 4: Security Controls, Evidence, Self-Protection, Resources panels

**Files:**
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusWindow.setOverallStatus`'s `/activity` fetch pattern from Task 3, extended the same way for `/controls` and `/evidence`; `/controls` JSON (`SecurityControls` struct already defined in `local_api_windows.go` — `defender.rtpEnabled`/`.present`/`.tamperProtected`, `sysmon.present`, `firewall.enabled`, `appLocker.enabled`, `wdac.enabled`, `amsi.enabled`); `/evidence` JSON (`LocalEvidenceStats` — `eventsCollected`, `defenderAlerts`, `sysmonDetections`, `uploadQueueSize`); `/status`'s `ramMB`/`agentVersion`/`agentId` (already fetched by Task 2, just needs rendering here).
- Produces: nothing new consumed by later tasks.

- [ ] **Step 1: Add the fields to `statusWindow`**

```go
	// Security Controls (6 rows: name + status text each)
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
	lblSpService  *ui.Static
	lblSpPolicy   *ui.Static
	lblSpQueue    *ui.Static
	lblSpUpload   *ui.Static
	lblSpContact  *ui.Static

	// Resources
	lblResRam     *ui.Static
	lblResVersion *ui.Static
	lblResId      *ui.Static
```

- [ ] **Step 2: Create the controls**

Add after the Current Operation panel's controls in `runStatusWindowNative`. Uses a plain vertical stack per section — real visual grouping (group boxes, section headers) is a polish item, not required for data parity, and left to whoever picks this up next if wanted:

```go
	// Security Controls
	sw.lblCtrlDefender = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Defender RTP: —").Position(ui.Dpi(16, 184)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlSysmon = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Sysmon: —").Position(ui.Dpi(16, 208)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlFirewall = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Firewall: —").Position(ui.Dpi(16, 232)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlAppLocker = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("AppLocker: —").Position(ui.Dpi(16, 256)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlWDAC = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("WDAC: —").Position(ui.Dpi(16, 280)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlAMSI = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("AMSI: —").Position(ui.Dpi(16, 304)).Size(ui.Dpi(340, 20)))

	// Evidence
	sw.lblEvEvents = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Events Collected: —").Position(ui.Dpi(400, 184)).Size(ui.Dpi(300, 20)))
	sw.lblEvDefender = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Defender Alerts: —").Position(ui.Dpi(400, 208)).Size(ui.Dpi(300, 20)))
	sw.lblEvSysmon = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Sysmon Detections: —").Position(ui.Dpi(400, 232)).Size(ui.Dpi(300, 20)))
	sw.lblEvQueue = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Upload Queue: —").Position(ui.Dpi(400, 256)).Size(ui.Dpi(300, 20)))

	// Self-Protection
	sw.lblSpService = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Service Running: —").Position(ui.Dpi(400, 288)).Size(ui.Dpi(300, 20)))
	sw.lblSpPolicy = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Policy Sync: —").Position(ui.Dpi(400, 312)).Size(ui.Dpi(300, 20)))
	sw.lblSpQueue = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Evidence Queue: —").Position(ui.Dpi(400, 336)).Size(ui.Dpi(300, 20)))
	sw.lblSpUpload = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Last Upload OK: —").Position(ui.Dpi(400, 360)).Size(ui.Dpi(300, 20)))
	sw.lblSpContact = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Server Contact: —").Position(ui.Dpi(400, 384)).Size(ui.Dpi(300, 20)))

	// Resources
	sw.lblResRam = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Memory: —").Position(ui.Dpi(16, 336)).Size(ui.Dpi(340, 20)))
	sw.lblResVersion = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Agent Version: —").Position(ui.Dpi(16, 360)).Size(ui.Dpi(340, 20)))
	sw.lblResId = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Agent ID: —").Position(ui.Dpi(16, 384)).Size(ui.Dpi(340, 20)))
```

- [ ] **Step 3: Extend `setOverallStatus` to fetch `/controls` and `/evidence`, and render Resources from `/status`**

Replace (Task 3's extension point, the `/activity` fetch block at the end of `setOverallStatus`):

```go
	var a map[string]interface{}
	if err := sw.client.getJSON("/activity", &a); err == nil {
		sw.setOperation(a)
	}
}
```

with:

```go
	sw.lblResRam.SetTextAndResize(fmt.Sprintf("Memory: %d MB", int(ramMB)))
	sw.lblResVersion.SetTextAndResize("Agent Version: v" + agentVersion)
	sw.lblResId.SetTextAndResize("Agent ID: " + agentId)

	var a map[string]interface{}
	if err := sw.client.getJSON("/activity", &a); err == nil {
		sw.setOperation(a)
	}

	var c map[string]interface{}
	if err := sw.client.getJSON("/controls", &c); err == nil {
		sw.setControls(c)
	}

	var ev map[string]interface{}
	if err := sw.client.getJSON("/evidence", &ev); err == nil {
		sw.setEvidence(ev)
	}

	sw.setSelfProtection(s, ev)
}

// setControls renders the Security Controls panel from a decoded
// /controls response (see SecurityControls in local_api_windows.go).
func (sw *statusWindow) setControls(c map[string]interface{}) {
	if d, ok := c["defender"].(map[string]interface{}); ok {
		present, _ := d["present"].(bool)
		rtp, _ := d["rtpEnabled"].(bool)
		tamper, _ := d["tamperProtected"].(bool)
		status := "ABSENT"
		if present {
			if rtp {
				status = "ACTIVE"
			} else {
				status = "DEGRADED"
			}
		}
		extra := ""
		if tamper {
			extra = " +Tamper"
		}
		sw.lblCtrlDefender.SetTextAndResize(fmt.Sprintf("Defender RTP: [%s]%s", status, extra))
	}
	setBoolControl := func(lbl *ui.Static, name string, m map[string]interface{}, key string) {
		on, _ := m[key].(bool)
		status := "ABSENT"
		if on {
			status = "ACTIVE"
		}
		lbl.SetTextAndResize(fmt.Sprintf("%s: [%s]", name, status))
	}
	if s, ok := c["sysmon"].(map[string]interface{}); ok {
		setBoolControl(sw.lblCtrlSysmon, "Sysmon", s, "present")
	}
	if f, ok := c["firewall"].(map[string]interface{}); ok {
		setBoolControl(sw.lblCtrlFirewall, "Firewall", f, "enabled")
	}
	if al, ok := c["appLocker"].(map[string]interface{}); ok {
		setBoolControl(sw.lblCtrlAppLocker, "AppLocker", al, "enabled")
	}
	if w, ok := c["wdac"].(map[string]interface{}); ok {
		setBoolControl(sw.lblCtrlWDAC, "WDAC", w, "enabled")
	}
	if am, ok := c["amsi"].(map[string]interface{}); ok {
		setBoolControl(sw.lblCtrlAMSI, "AMSI", am, "enabled")
	}
}

// setEvidence renders the Evidence tiles from a decoded /evidence response.
func (sw *statusWindow) setEvidence(ev map[string]interface{}) {
	events, _ := ev["eventsCollected"].(float64)
	defenderAlerts, _ := ev["defenderAlerts"].(float64)
	sysmonDetections, _ := ev["sysmonDetections"].(float64)
	queue, _ := ev["uploadQueueSize"].(float64)
	sw.lblEvEvents.SetTextAndResize(fmt.Sprintf("Events Collected: %d", int(events)))
	sw.lblEvDefender.SetTextAndResize(fmt.Sprintf("Defender Alerts: %d", int(defenderAlerts)))
	sw.lblEvSysmon.SetTextAndResize(fmt.Sprintf("Sysmon Detections: %d", int(sysmonDetections)))
	sw.lblEvQueue.SetTextAndResize(fmt.Sprintf("Upload Queue: %d", int(queue)))
}

// setSelfProtection renders the Self-Protection rows. Matches the old HTML
// page's renderSelfProt(s, ev) -- s is /status's decoded body (already
// available in setOverallStatus's scope), ev is /evidence's (may be nil if
// that fetch failed, matching the HTML version's "!ev ||" queue-health check).
func (sw *statusWindow) setSelfProtection(s map[string]interface{}, ev map[string]interface{}) {
	serviceRunning, _ := s["serviceRunning"].(bool)
	state, _ := s["state"].(string)
	lastUploadOk, _ := s["lastUploadOk"].(bool)
	serverConnected, _ := s["serverConnected"].(bool)

	queueHealthy := true
	if ev != nil {
		queueSize, _ := ev["uploadQueueSize"].(float64)
		queueHealthy = queueSize < 100
	}

	setRow := func(lbl *ui.Static, name string, on bool) {
		status := "CHECK"
		if on {
			status = "HEALTHY"
		}
		lbl.SetTextAndResize(fmt.Sprintf("%s: %s", name, status))
	}
	setRow(sw.lblSpService, "Service Running", serviceRunning)
	setRow(sw.lblSpPolicy, "Policy Sync", state == "active" || state == "restricted")
	setRow(sw.lblSpQueue, "Evidence Queue", queueHealthy)
	setRow(sw.lblSpUpload, "Last Upload OK", lastUploadOk)
	setRow(sw.lblSpContact, "Server Contact", serverConnected)
}
```

- [ ] **Step 4: Build**

```bash
go build ./...
```

Expected: succeeds.

- [ ] **Step 5: Commit**

```bash
git add statuswindow_windows.go
git commit -m "feat(agent): native status window - controls/evidence/self-protection/resources panels"
git push
```

---

### Task 5: Activity feed and action buttons

**Files:**
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `/activity`'s `recentActivity` array (`time`, `event` fields, already served by `handleLocalActivity`); `exportDiagnosticBundle()` and `revealInExplorer()` (existing functions — `exportDiagnosticBundle` is defined elsewhere in the `agent` package, already used by `tray_windows.go`'s `tIDM_EXPORT` menu handler, confirmed to exist and take no arguments, returning `(path string, err error)`).
- Produces: nothing consumed by later tasks — this is the last panel.

- [ ] **Step 1: Add the fields to `statusWindow`**

```go
	listActivity *ui.ListView
	btnExport    *ui.Button
	btnDashboard *ui.Button
	lastServerURL string
```

- [ ] **Step 2: Create the controls**

Add after the Resources panel's controls in `runStatusWindowNative`:

```go
	sw.listActivity = ui.NewListView(sw.wnd, ui.OptsListView().
		Position(ui.Dpi(16, 416)).Size(ui.Dpi(684, 140)))
	sw.listActivity.Cols().Add("Time", ui.Dpi(100))
	sw.listActivity.Cols().Add("Event", ui.Dpi(560))

	sw.btnExport = ui.NewButton(sw.wnd, ui.OptsButton().
		Text("Export Diagnostic Bundle").Position(ui.Dpi(16, 568)).Size(ui.Dpi(200, 28)))
	sw.btnDashboard = ui.NewButton(sw.wnd, ui.OptsButton().
		Text("Open BAS Console").Position(ui.Dpi(232, 568)).Size(ui.Dpi(160, 28)))
```

- [ ] **Step 3: Wire the button click handlers**

Add after control creation, before `sw.wnd.On().WmTimer(...)`:

```go
	sw.btnExport.On().BnClicked(func() {
		if path, err := exportDiagnosticBundle(); err == nil {
			revealInExplorer(path)
		}
	})
	sw.btnDashboard.On().BnClicked(func() {
		if sw.lastServerURL != "" {
			openInBrowser(sw.lastServerURL)
		}
	})
```

Note: unlike the old HTML page (which needed `window.basExport`/`window.basOpenDashboard` host-binding checks that never worked, since WebView2 never actually hosted the page), this native window calls `exportDiagnosticBundle()` and `openInBrowser()` directly — they're regular Go functions in the same process, no binding layer needed.

- [ ] **Step 4: Extend `setOverallStatus` to record `serverUrl` and render the activity feed**

Replace (Task 4's extension point, the final lines of `setOverallStatus`):

```go
	sw.setSelfProtection(s, ev)
}
```

with:

```go
	if serverURL != "" {
		sw.lastServerURL = serverURL
	}
	sw.setSelfProtection(s, ev)
	if a != nil {
		sw.setActivity(a)
	}
}

// setActivity renders the Recent Activity list from a decoded /activity
// response's recentActivity field. Matches the old HTML page's
// renderActivity() -- most-recent-first, same as handleLocalActivity
// already returns it.
func (sw *statusWindow) setActivity(a map[string]interface{}) {
	sw.listActivity.DeleteAllItems()
	items, ok := a["recentActivity"].([]interface{})
	if !ok || len(items) == 0 {
		sw.listActivity.AddItem("—", "No recent activity recorded.")
		return
	}
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		t, _ := item["time"].(string)
		event, _ := item["event"].(string)
		displayTime := "—"
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			displayTime = parsed.Format("15:04:05")
		}
		sw.listActivity.AddItem(displayTime, event)
	}
}
```

- [ ] **Step 5: Build**

```bash
go build ./...
```

Expected: succeeds. If `exportDiagnosticBundle`'s real signature differs from `(path string, err error)` (assumed above, based on its existing call site in `tray_windows.go`'s `tIDM_EXPORT` handler: `if path, err := exportDiagnosticBundle(); err == nil { revealInExplorer(path) }`), this build step is where that mismatch would surface — that existing call site is the actual ground truth, already correct in the codebase today, so Step 3 above mirrors it exactly and should compile without changes.

- [ ] **Step 6: Commit**

```bash
git add statuswindow_windows.go
git commit -m "feat(agent): native status window - activity feed + export/dashboard buttons"
git push
```

---

### Task 6: Fix stale comments, final verification, cross-compile check

**Files:**
- Modify: `agent/platform_windows.go` (flag description)
- Modify: `agent/tray_windows.go` (doc comment)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing — this is the closing task.

- [ ] **Step 1: Fix the stale flag description**

In `agent/platform_windows.go`, replace (currently line 49):

```go
	flagStatusWindow = flag.Bool("status-window", false, "Open the WebView2 status console (user session)")
```

with:

```go
	flagStatusWindow = flag.Bool("status-window", false, "Open the native status console (user session)")
```

- [ ] **Step 2: Fix the stale tray doc comment**

In `agent/tray_windows.go`, replace (currently lines 145-146):

```go
// runTray shows the persistent system-tray icon. Left-click / double-click opens
// the WebView2 status console (spawned as a separate --status-window process).
```

with:

```go
// runTray shows the persistent system-tray icon. Left-click / double-click opens
// the native status console (spawned as a separate --status-window process).
```

- [ ] **Step 3: Full native build + cross-compile checks**

```bash
cd agent
go build ./...
go vet ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=amd64 go build ./...
```

Expected: native build and vet succeed (this is the real, full compile against the real `windigo` dependency). Both cross-compiles succeed too — `statuswindow_windows.go` and the `windigo` import are behind `//go:build windows`, so they're excluded from non-Windows builds entirely; this just confirms nothing broke the shared cross-platform code.

- [ ] **Step 4: Manual run — flag as required, cannot be done by the agent**

This environment cannot render or interact with a native Win32 window. Before considering this feature production-ready, run it for real:

1. Build the agent (`go build -o bas_agent.exe .` or via `packaging/windows-build.ps1`), install/run it, and click the tray icon.
2. Confirm the native window opens (not a browser tab) and shows live data that matches what `curl -H "Authorization: Bearer <token>" http://127.0.0.1:9001/status` returns directly.
3. Start a scenario run from the BAS console and confirm the Current Operation panel updates within 5 seconds.
4. Click **Export Diagnostic Bundle** — confirm it behaves identically to the tray's existing "Export Diagnostic Bundle" menu item (same function, called directly now).
5. Click **Open BAS Console** — confirm it opens the real web admin console in the browser.
6. Stop the `BASAgent` service and confirm the window shows the offline state within one poll cycle (5s) instead of hanging or crashing.
7. If any of the above fails, report back — do not consider this feature done until a real run confirms it.

- [ ] **Step 5: Commit**

```bash
git add platform_windows.go tray_windows.go
git commit -m "$(cat <<'EOF'
chore(agent): fix stale WebView2 comments now that the console is native

Two doc/flag-description strings still described the status console
as WebView2-hosted after it became a native windigo window in the
preceding tasks.
EOF
)"
git push
```

---

## Self-Review Notes

- **Spec coverage:** Every panel from the approved design has a task — hero/connection (Task 2), current operation (Task 3), security controls/evidence/self-protection/resources (Task 4), activity feed + action buttons (Task 5). The windigo dependency, real-API verification step, and window shell + fallback-to-browser logic are Task 1. Stale-comment fixes and the mandatory manual-run gate are Task 6.
- **Placeholder scan:** No TBD/TODO. Every step shows real code built on the verified `windigo` API surface (`ui.NewMain`/`NewStatic`/`NewButton`/`NewProgressBar`/`NewListView`, `.SetTextAndResize`/`.SetPos`/`.SetRange`/`.AddItem`/`.DeleteAllItems`, `.On().BnClicked`, `.On().WmTimer`, `.RunAsMain()`) confirmed against the real package docs before writing any control-wiring code. Task 1 Step 2's `go doc` calls are a real, concrete verification action, not a stand-in for design work — this plan is honest that windigo is a less-common library and names one explicit point where the implementer double-checks method names against ground truth before building on them, exactly the same spirit as this session's "re-verify current line numbers before editing" convention applied to an external API instead of this repo's own code.
- **Type consistency:** `statusWindow` struct fields are added incrementally per task and referenced consistently — Task 2's `lblConnServer` etc. match what Task 2's own `setOverallStatus` uses; Task 3's `setOperation` is called from Task 2's `setOverallStatus` extension point using the same method name across both tasks; Task 4 and Task 5 each extend `setOverallStatus` at the exact point the prior task left it, verified by quoting that prior task's literal closing lines as the "replace" target.
- **Scope check:** Decomposed by panel/deliverable, matching the "split where a reviewer could meaningfully approve one task while rejecting its neighbor" guidance — e.g. the Security Controls panel (Task 4) is a materially different reviewable unit from the Activity feed + buttons (Task 5), even though both are "more UI panels," because Task 5 introduces the only two side-effecting actions (export, open browser) in the whole window, worth its own review gate.
