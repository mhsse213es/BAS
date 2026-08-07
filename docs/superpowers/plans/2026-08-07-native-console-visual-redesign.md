# Native Status Console Visual Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the native Win32 status console's rendering from stock windigo controls to fully owner-drawn GDI, so it visually matches the existing dark card-based browser dashboard instead of the default flat-grey Windows theme.

**Architecture:** Same 4-layer flow as before (`statusclient` → `StatusSnapshot`/`StatusWindow` → `StatusController` → presentation) — only the presentation layer changes. `agent/statuswindow_windows.go` keeps window lifecycle (`Show`/`Close`/`Refresh`) but stores the latest snapshot and triggers `InvalidateRect` instead of mutating stock controls. A new `agent/statuscanvas_windows.go` holds palette/font/brush/pen resources and every drawing primitive, driven by one `WM_PAINT` handler that renders the full frame from the stored snapshot.

**Tech Stack:** Go, `github.com/rodrigocfd/windigo` (`ui` package for window/message-loop, `win` package for raw GDI calls), `golang.org/x/sys/windows` (unchanged, for `ShellExecuteW`).

## Global Constraints

- Palette (verbatim from spec, `win.RGB` values): bg `#0b1420`, card `#152338`, elevated `#1b2a41`, border `#22324a`, accent `#2f81f7`, muted `#9aa9bc`, success `#238636`, warning `#d29922`, danger `#da3633`, text `#e6edf3`.
- Font: Segoe UI only, three weights/sizes (Semibold hero ~27px, Semibold heading ~17px, Regular body ~14px, Semibold/Regular eyebrow ~12px) — all `//go:build windows`.
- No scrolling, no window resizing, no GDI+, no embedded fonts, no bitmap icons — hand-drawn GDI vector glyphs only.
- Layout grid: 24px page margin, 16px inter-card gap, 16px card internal padding, all multiplied by `ui.Dpi(...)` exactly like today's `dpiPos` helper.
- `statusclient`/`statuscontroller`/`StatusWindow` interface/`StatusSnapshot` are unmodified — do not touch `agent/statusclient/*`, `agent/statuswindow.go`, `agent/statuscontroller.go`, `agent/statuscontroller_test.go`, `agent/browserwindow_windows.go`.
- Every new/changed Windows-only file keeps `//go:build windows`. Run `go build ./...`, `go vet ./...`, `go test ./...`, `GOOS=linux go build ./...`, `GOOS=darwin go build ./...` from `agent/` after every task.
- Manual verification per task: build `bas_agent_test.exe`, run `--status-window` against a live agent (test binary or the real installed `BASAgent` service, whichever is running — read-only polling, never touches the real service), capture via the session's established `PrintWindow` + `GetWindowRect` PowerShell technique, view the PNG.

---

## Layout Reference (all values pre-DPI-scaling, i.e. pass through `dpiPos`)

Window client size: `920 x 1320` (starting value — Task 1 verifies and adjusts by the same trial-and-screenshot process that fixed the 720→920 width earlier this session).

Content column: `x=24` to `x=896` (width 872). Two-column split: col A `x=24` width `428`; col B `x=468` width `428`.

| Section | y | height | Notes |
|---|---|---|---|
| Page header (no card) | 16 | 56 | ends 72 |
| Hero card | 88 | 100 | ends 188 |
| Connection card (col A) / Current Operation card (col B) | 204 | 190 | ends 394 |
| Endpoint Security Controls card (full width) | 410 | 190 | ends 600 |
| Evidence card (col A) / Self-Protection card (col B) | 616 | 210 | ends 826 |
| Resources card (full width) | 842 | 130 | ends 972 |
| Recent Activity card (full width) | 988 | 240 | ends 1228 |
| Action row (no card) | 1244 | 36 | ends 1280 |

Bottom margin 24 → window content ends ~1304; window client height rounds up to 1320.

---

## Task 1: Palette/font/brush resource cache + window plumbing (dark blank window)

**Files:**
- Create: `agent/statuscanvas_windows.go`
- Modify: `agent/statuswindow_windows.go` (full rewrite of `windigoWindow` struct, `newWindigoWindow`, `Refresh`, `render*` methods)
- Test: none (GDI painting isn't unit-testable; verified via screenshot per this task's Step 6)

**Interfaces:**
- Consumes: `StatusSnapshot` (`agent/statuswindow.go`, unchanged), `StatusController` (`agent/statuscontroller.go`, unchanged: `NewStatusController`, `.Run()`, `.Stop()`, `.ExportDiagnostics()`, `.OpenDashboard(serverURL string)`).
- Produces: `type resources struct{...}` (palette brushes/pens/fonts, built once) consumed by every later task's drawing code; `type windigoWindow struct { wnd *ui.Main; controller *StatusController; res *resources; latest StatusSnapshot; buttons []buttonHitRect }` — later tasks add fields to this struct and drawing calls inside its paint routine; `type buttonHitRect struct { rc win.RECT; onClick func() }`.

- [ ] **Step 1: Define the palette and resource cache in `agent/statuscanvas_windows.go`**

```go
//go:build windows

package main

import (
	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
)

var (
	colBg       = win.RGB(0x0b, 0x14, 0x20)
	colCard     = win.RGB(0x15, 0x23, 0x38)
	colElevated = win.RGB(0x1b, 0x2a, 0x41)
	colBorder   = win.RGB(0x22, 0x32, 0x4a)
	colAccent   = win.RGB(0x2f, 0x81, 0xf7)
	colMuted    = win.RGB(0x9a, 0xa9, 0xbc)
	colSuccess  = win.RGB(0x23, 0x86, 0x36)
	colWarning  = win.RGB(0xd2, 0x99, 0x22)
	colDanger   = win.RGB(0xda, 0x36, 0x33)
	colText     = win.RGB(0xe6, 0xed, 0xf3)
)

// resources holds every GDI object the canvas needs, created once at window
// creation and released on WM_DESTROY. Recreating brushes/pens/fonts on
// every WM_PAINT would leak GDI handles (CreateFont/CreatePen/
// CreateBrushIndirect all require a matching DeleteObject).
type resources struct {
	brushBg       win.HBRUSH
	brushCard     win.HBRUSH
	brushElevated win.HBRUSH
	brushAccent   win.HBRUSH

	penBorder win.HPEN

	fontHero    win.HFONT // Segoe UI Semibold, big state word
	fontHeading win.HFONT // Segoe UI Semibold, card titles
	fontBody    win.HFONT // Segoe UI Regular, labels/values
	fontEyebrow win.HFONT // Segoe UI Semibold, small uppercase section labels
}

func solidBrush(color win.COLORREF) win.HBRUSH {
	b, _ := win.CreateBrushIndirect(&win.LOGBRUSH{Style: co.BRS_SOLID, Color: color})
	return b
}

func segoeFont(height int, weight co.FW) win.HFONT {
	_, h := dpiPos(0, height)
	f, _ := win.CreateFont(
		h, 0, 0, 0, int(weight),
		false, false, false,
		co.CHARSET_DEFAULT, co.OUT_PRECIS_DEFAULT, co.CLIP_PRECIS_DEFAULT,
		co.QUALITY_CLEARTYPE, co.PITCH_DEFAULT, co.FF_DONTCARE,
		"Segoe UI",
	)
	return f
}

func newResources() *resources {
	r := &resources{
		brushBg:       solidBrush(colBg),
		brushCard:     solidBrush(colCard),
		brushElevated: solidBrush(colElevated),
		brushAccent:   solidBrush(colAccent),
		fontHero:      segoeFont(-27, co.FW_SEMIBOLD),
		fontHeading:   segoeFont(-17, co.FW_SEMIBOLD),
		fontBody:      segoeFont(-14, co.FW_REGULAR),
		fontEyebrow:   segoeFont(-12, co.FW_SEMIBOLD),
	}
	r.penBorder, _ = win.CreatePen(co.PS_SOLID, 1, colBorder)
	return r
}

func (r *resources) release() {
	r.brushBg.DeleteObject()
	r.brushCard.DeleteObject()
	r.brushElevated.DeleteObject()
	r.brushAccent.DeleteObject()
	r.penBorder.DeleteObject()
	r.fontHero.DeleteObject()
	r.fontHeading.DeleteObject()
	r.fontBody.DeleteObject()
	r.fontEyebrow.DeleteObject()
}
```

- [ ] **Step 2: Add the card-drawing primitive (used by every later task)**

Append to `agent/statuscanvas_windows.go`:

```go
func dpiRect(x, y, cx, cy int) win.RECT {
	x, y = dpiPos(x, y)
	cx, cy = dpiPos(cx, cy)
	return win.RECT{Left: int32(x), Top: int32(y), Right: int32(x + cx), Bottom: int32(y + cy)}
}

// drawCard paints a rounded-rectangle card: card-colored fill, 1px border.
func (r *resources) drawCard(hdc win.HDC, rc win.RECT) {
	hdc.SelectObjectBrush(r.brushCard)
	hdc.SelectObjectPen(r.penBorder)
	cornerCx, cornerCy := dpiPos(8, 8)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cornerCx), Cy: int32(cornerCy)})
}

// drawText draws a single line of text with the given font/color, left-
// aligned and vertically centered within rc.
func (r *resources) drawText(hdc win.HDC, text string, rc win.RECT, font win.HFONT, color win.COLORREF, align co.DT) {
	hdc.SelectObjectFont(font)
	hdc.SetTextColor(color)
	hdc.SetBkMode(co.BKMODE_TRANSPARENT)
	hdc.DrawText(text, &rc, align|co.DT_SINGLELINE|co.DT_VCENTER|co.DT_END_ELLIPSIS)
}
```

Check the exact `co.BKMODE` constant name before using it:

```bash
grep -n "BKMODE_TRANSPARENT\|BKMODE_OPAQUE" "$(go env GOPATH)/pkg/mod/github.com/rodrigocfd/windigo@v0.2.6/co/"*.go
```

If the constant name differs from `co.BKMODE_TRANSPARENT`, use the actual name found — do not guess.

- [ ] **Step 3: Rewrite `agent/statuswindow_windows.go` window plumbing**

Replace the entire file content from `type windigoWindow struct` (line 80) through the end of `newWindigoWindow` (line 239) with:

```go
type buttonHitRect struct {
	rc      win.RECT
	onClick func()
}

// windigoWindow implements StatusWindow as a real native Win32 window
// (github.com/rodrigocfd/windigo -- pure Go, zero CGo), fully owner-drawn
// (see agent/statuscanvas_windows.go) to match the browser dashboard's
// dark card-based design instead of the default flat-grey OS theme. Pure
// presentation: it never calls statusclient or agent business logic
// itself -- every button handler forwards to controller (set by
// runStatusWindow right after construction, since StatusController's own
// constructor needs a StatusWindow reference, creating the
// chicken-and-egg this two-step wiring resolves).
type windigoWindow struct {
	wnd        *ui.Main
	controller *StatusController
	res        *resources

	latest  StatusSnapshot
	buttons []buttonHitRect
}

func newWindigoWindow() *windigoWindow {
	sw := &windigoWindow{res: newResources()}

	cx, cy := ui.Dpi(920, 1320)
	sw.wnd = ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent").
			Size(cx, cy).
			ClassBrush(sw.res.brushBg),
	)

	sw.wnd.On().WmCreate(func(p ui.WmCreate) int {
		sw.wnd.Hwnd().DwmSetWindowAttribute(win.DwmAttrUseImmersiveDarkMode(true))
		return 0
	})

	sw.wnd.On().WmEraseBkgnd(func(p ui.WmEraseBkgnd) int {
		return 1 // we paint the whole background ourselves in WmPaint
	})

	sw.wnd.On().WmPaint(func() {
		var ps win.PAINTSTRUCT
		hdc, _ := sw.wnd.Hwnd().BeginPaint(&ps)
		defer sw.wnd.Hwnd().EndPaint(&ps)

		clientRc, _ := sw.wnd.Hwnd().GetClientRect()
		hdc.FillRect(&clientRc, sw.res.brushBg)

		sw.buttons = sw.paint(hdc)
	})

	sw.wnd.On().WmLButtonUp(func(p ui.WmMouse) {
		pt := p.Pos()
		for _, b := range sw.buttons {
			if int32(pt.X) >= b.rc.Left && int32(pt.X) <= b.rc.Right &&
				int32(pt.Y) >= b.rc.Top && int32(pt.Y) <= b.rc.Bottom {
				b.onClick()
				return
			}
		}
	})

	sw.wnd.On().WmDestroy(func() {
		sw.res.release()
	})

	return sw
}

// dpiPos is a small local wrapper around ui.Dpi so every coordinate call
// site in this file and statuscanvas_windows.go can pass a single (x,y)
// pair without repeating the two-return-value ui.Dpi(x,y) call inline
// everywhere.
func dpiPos(x, y int) (int, int) { return ui.Dpi(x, y) }
```

- [ ] **Step 4: Replace `render`/`renderActivity`/`activityFingerprint`/`renderControls`/`renderEvidence`/`renderSelfProtection`/`renderOperation` (lines 264-435 of the original file) with a stub `paint` method**

```go
// paint draws the full frame from sw.latest and returns the current
// button hit-rects (recomputed every paint since layout is static).
// Later tasks extend this method section by section; this task only
// establishes the empty dark canvas.
func (sw *windigoWindow) paint(hdc win.HDC) []buttonHitRect {
	return nil
}
```

- [ ] **Step 5: Update `Show`/`Close`/`Refresh` (keep `orDash`/`formatUptime`, delete `activityFingerprint` — its only purpose was gating `ListView` rebuild churn, which no longer exists once the whole frame repaints cheaply via GDI on every poll tick)**

```go
func (sw *windigoWindow) Show() error {
	sw.wnd.RunAsMain()
	return nil
}

func (sw *windigoWindow) Close() {
	_ = sw.wnd.Hwnd().DestroyWindow()
}

// Refresh is called by StatusController from its own polling goroutine,
// never the UI thread. Win32 controls (and GDI calls against this
// window's DC) may only be touched from the thread that owns the message
// loop (RunAsMain), so this marshals both the snapshot store and the
// repaint request onto that thread via windigo's UiThread.
func (sw *windigoWindow) Refresh(snap StatusSnapshot) {
	sw.wnd.UiThread(func() {
		sw.latest = snap
		sw.wnd.Hwnd().InvalidateRect(nil, false)
	})
}
```

`activityFingerprint` was never unit-tested in a separate `_test.go` file (only `statusclient` and `statuscontroller` have test coverage — see Task 1/3 of the original plan) and lived solely in `statuswindow_windows.go`, so deleting it in this step's replacement of lines 264-435 is a plain removal with nothing else to clean up. Confirm this before deleting: `grep -rn activityFingerprint agent/*.go` should, after Steps 3-4 are applied, return zero matches.

- [ ] **Step 6: Build, cross-compile, and screenshot-verify**

```bash
cd agent
go build -o bas_agent_test.exe .
go vet ./...
go test ./...
GOOS=linux go build ./...
GOOS=darwin go build ./...
```

Run `./bas_agent_test.exe --status-window &`, then capture with the session's established PowerShell `PrintWindow` script (see this session's transcript for the exact script — `GetWindowRect` + `PrintWindow(hwnd, hdc, 2)` + `Bitmap.Save`), and view the PNG.

Expected: a solid dark-navy (`#0b1420`) window, correct size (~920x1320 scaled by DPI), dark title bar, no visible content yet (that's Task 2+), no flicker/crash, process exits cleanly on close.

- [ ] **Step 7: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "refactor(agent): owner-drawn GDI foundation for native status console

Replaces stock windigo controls with a WM_PAINT-driven canvas (palette,
fonts, brushes, card primitive) to match the browser dashboard's dark
card-based design. This task lands the empty dark canvas; Tasks 2-7 add
each card section's content."
```

---

## Task 2: Page header + Hero card

**Files:**
- Modify: `agent/statuscanvas_windows.go` (add icon glyphs + header/hero drawing)
- Modify: `agent/statuswindow_windows.go` (`paint` method)

**Interfaces:**
- Consumes: `resources` (Task 1), `StatusSnapshot.Online`, `.Status.{Hostname,ServerConnected,Paused,State,AgentVersion}` (unchanged field names from `agent/statusclient/statusclient.go`).
- Produces: `func (r *resources) drawIconShield(hdc win.HDC, x, y, size int, color win.COLORREF)`, `func (r *resources) drawHeader(hdc win.HDC, snap StatusSnapshot)`, `func (r *resources) drawHero(hdc win.HDC, snap StatusSnapshot) win.COLORREF` (returns the state's accent color, reused by later cards if needed) — both called from `windigoWindow.paint`.

- [ ] **Step 1: Add the shield icon glyph and status-dot primitive to `agent/statuscanvas_windows.go`**

```go
func (r *resources) drawDot(hdc win.HDC, x, y, diameter int, color win.COLORREF) {
	x2, y2 := dpiPos(x, y)
	d, _ := dpiPos(diameter, 0)
	brush := solidBrush(color)
	defer brush.DeleteObject()
	hdc.SelectObjectBrush(brush)
	hdc.SelectObjectPen(r.penBorder)
	hdc.Ellipse(win.RECT{Left: int32(x2), Top: int32(y2), Right: int32(x2 + d), Bottom: int32(y2 + d)})
}

// drawIconShield draws a simple pentagon shield outline, used for the
// header badge and (reused, colored per-status) the Endpoint Security
// Controls card header.
func (r *resources) drawIconShield(hdc win.HDC, x, y, size int, color win.COLORREF) {
	pen, _ := win.CreatePen(co.PS_SOLID, 2, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	hdc.SelectObjectBrush(r.brushCard) // unfilled look: fill matches card bg
	pts := []win.POINT{
		{X: int32(x + size/2), Y: int32(y)},
		{X: int32(x + size), Y: int32(y + size/4)},
		{X: int32(x + size), Y: int32(y + size/2)},
		{X: int32(x + size/2), Y: int32(y + size)},
		{X: int32(x), Y: int32(y + size/2)},
		{X: int32(x), Y: int32(y + size/4)},
	}
	hdc.Polygon(pts)
}
```

- [ ] **Step 2: Add `stateColor` + `drawHeader` + `drawHero` to `agent/statuscanvas_windows.go`**

```go
// stateColor maps the same connection/lifecycle state logic used
// throughout the dashboard (ServerConnected/Paused/State) to one of the
// three semantic accent colors, so the hero card's left bar, the header
// status pill, and later cards' badges all agree on what "healthy" means.
func stateColor(s statusclient.StatusResponse) win.COLORREF {
	switch {
	case !s.ServerConnected && s.Paused:
		return colWarning
	case !s.ServerConnected:
		return colDanger
	case s.State == "quarantined" || s.State == "restricted":
		return colDanger
	default:
		return colSuccess
	}
}

func stateLabel(s statusclient.StatusResponse) string {
	switch {
	case !s.ServerConnected && s.Paused:
		return "Paused"
	case !s.ServerConnected:
		return "Disconnected"
	case s.State == "quarantined":
		return "Quarantined"
	case s.State == "restricted":
		return "Restricted"
	case s.State == "active":
		return "Active"
	default:
		return "Idle"
	}
}

func (r *resources) drawHeader(hdc win.HDC, snap StatusSnapshot) {
	badgeRc := dpiRect(24, 16, 40, 40)
	hdc.SelectObjectBrush(r.brushAccent)
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(10, 10)
	hdc.RoundRect(badgeRc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	r.drawIconShield(hdc, badgeRc.Left+int32(dpiXOnly(10)), badgeRc.Top+int32(dpiXOnly(10)), dpiXOnly(20), colText)

	r.drawText(hdc, "Audspect BAS Agent", dpiRect(76, 18, 400, 22), r.fontHeading, colText, co.DT_LEFT)
	r.drawText(hdc, "Breach & Attack Simulation · Endpoint Defense Validation", dpiRect(76, 40, 500, 18), r.fontBody, colMuted, co.DT_LEFT)

	if !snap.Online {
		r.drawText(hdc, "Agent Unreachable", dpiRect(700, 26, 196, 20), r.fontBody, colDanger, co.DT_RIGHT)
		return
	}
	s := snap.Status
	r.drawDot(hdc, 700, 30, 10, stateColor(s))
	r.drawText(hdc, stateLabel(s), dpiRect(716, 26, 180, 20), r.fontBody, colText, co.DT_LEFT)
}

func (r *resources) drawHero(hdc win.HDC, snap StatusSnapshot) {
	rc := dpiRect(24, 88, 872, 100)
	r.drawCard(hdc, rc)

	if !snap.Online {
		barRc := dpiRect(24, 88, 4, 100)
		hdc.SelectObjectBrush(solidBrush(colDanger))
		hdc.Rectangle(barRc)
		r.drawText(hdc, "ENDPOINT PROTECTION STATUS", dpiRect(56, 104, 400, 16), r.fontEyebrow, colMuted, co.DT_LEFT)
		r.drawText(hdc, "Agent Unreachable", dpiRect(56, 122, 400, 36), r.fontHero, colDanger, co.DT_LEFT)
		r.drawText(hdc, "The local agent service is not responding.", dpiRect(56, 160, 500, 18), r.fontBody, colMuted, co.DT_LEFT)
		return
	}
	s := snap.Status
	accent := stateColor(s)
	barBrush := solidBrush(accent)
	defer barBrush.DeleteObject()
	hdc.SelectObjectBrush(barBrush)
	hdc.Rectangle(dpiRect(24, 88, 4, 100))

	r.drawText(hdc, "ENDPOINT PROTECTION STATUS", dpiRect(56, 104, 400, 16), r.fontEyebrow, colMuted, co.DT_LEFT)
	r.drawText(hdc, stateLabel(s), dpiRect(56, 122, 400, 36), r.fontHero, colText, co.DT_LEFT)
	desc := "Agent healthy and connected. No simulation is running."
	if s.State == "quarantined" || s.State == "restricted" {
		desc = "Agent integrity check failed — server has been notified."
	} else if s.Paused {
		desc = "Server link lost — run continues locally if one is active."
	}
	r.drawText(hdc, desc, dpiRect(56, 160, 500, 18), r.fontBody, colMuted, co.DT_LEFT)

	r.drawText(hdc, s.Hostname, dpiRect(696, 104, 176, 20), r.fontBody, colText, co.DT_RIGHT)
	r.drawText(hdc, "HOSTNAME", dpiRect(696, 124, 176, 16), r.fontEyebrow, colMuted, co.DT_RIGHT)
}
```

Add the small helper `dpiXOnly` (single-axis DPI scale, needed because `drawIconShield`'s size/offset args are scalars, not (x,y) pairs):

```go
func dpiXOnly(v int) int {
	scaled, _ := dpiPos(v, 0)
	return scaled
}
```

Verify `statusclient.StatusResponse` field names (`Hostname`, `ServerConnected`, `Paused`, `State`, `AgentVersion`) against `agent/statusclient/statusclient.go` before using them — they must match exactly what Task 1 of the original plan defined.

- [ ] **Step 3: Wire into `paint` in `agent/statuswindow_windows.go`**

```go
func (sw *windigoWindow) paint(hdc win.HDC) []buttonHitRect {
	sw.res.drawHeader(hdc, sw.latest)
	sw.res.drawHero(hdc, sw.latest)
	return nil
}
```

- [ ] **Step 4: Build, cross-compile, screenshot-verify**

Same commands as Task 1 Step 6. Expected: dark window with the accent-badge header (title, subtitle, state pill) and the hero card (colored left bar, big state word, description, hostname) rendering correctly for both online and offline (`Online: false`) cases — test offline by pointing `--status-window` at a port nothing is listening on, or by killing the underlying agent process as done earlier this session.

- [ ] **Step 5: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "feat(agent): owner-drawn header + hero card for native status console"
```

---

## Task 3: Connection + Current Operation cards

**Files:**
- Modify: `agent/statuscanvas_windows.go`
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusclient.StatusResponse.{ServerURL,UptimeSec,LastHeartbeat}` (from Task 1's `statusclient` package, unchanged), `statusclient.ActivityResponse.{CurrentOperation,LastOperation}`, `statusclient.Operation.{ScenarioName,TechniqueID,TotalSteps,Phase,Progress,Result,DurationSec,Running}` (all field names exactly as defined in `agent/statusclient/statusclient.go` — re-read that file's struct definitions before writing this task's code if any name is uncertain).
- Produces: `func (r *resources) drawConnectionCard(hdc win.HDC, snap StatusSnapshot)`, `func (r *resources) drawOperationCard(hdc win.HDC, a statusclient.ActivityResponse)`, `func (r *resources) drawIconSignal(hdc win.HDC, x, y, size int, color win.COLORREF)`, `func (r *resources) drawIconClock(hdc win.HDC, x, y, size int, color win.COLORREF)`, `func (r *resources) drawProgressBar(hdc win.HDC, rc win.RECT, pct int)`.

- [ ] **Step 1: Add signal-bars and clock icon glyphs**

```go
func (r *resources) drawIconSignal(hdc win.HDC, x, y, size int, color win.COLORREF) {
	brush := solidBrush(color)
	defer brush.DeleteObject()
	hdc.SelectObjectBrush(brush)
	hdc.SelectObjectPen(r.penBorder)
	barW := size / 4
	heights := []int{size / 3, size * 2 / 3, size}
	for i, h := range heights {
		bx := x + i*(barW+2)
		by := y + size - h
		hdc.Rectangle(win.RECT{Left: int32(bx), Top: int32(by), Right: int32(bx + barW), Bottom: int32(y + size)})
	}
}

func (r *resources) drawIconClock(hdc win.HDC, x, y, size int, color win.COLORREF) {
	pen, _ := win.CreatePen(co.PS_SOLID, 2, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	hdc.SelectObjectBrush(r.brushCard)
	hdc.Ellipse(win.RECT{Left: int32(x), Top: int32(y), Right: int32(x + size), Bottom: int32(y + size)})
	cx, cy := x+size/2, y+size/2
	hdc.MoveToEx(cx, cy)
	hdc.LineTo(cx, y+size/4)
	hdc.MoveToEx(cx, cy)
	hdc.LineTo(cx+size/4, cy)
}
```

- [ ] **Step 2: Add the progress bar primitive**

```go
func (r *resources) drawProgressBar(hdc win.HDC, rc win.RECT, pct int) {
	hdc.SelectObjectBrush(r.brushElevated)
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(4, 4)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	if pct <= 0 {
		return
	}
	if pct > 100 {
		pct = 100
	}
	filled := rc
	filled.Right = rc.Left + (rc.Right-rc.Left)*int32(pct)/100
	fillBrush := solidBrush(colAccent)
	defer fillBrush.DeleteObject()
	hdc.SelectObjectBrush(fillBrush)
	hdc.RoundRect(filled, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
}
```

- [ ] **Step 3: Add `drawConnectionCard` and `drawOperationCard`**

First re-read `agent/statusclient/statusclient.go` to confirm exact field names on `Operation`:

```bash
grep -n "type Operation struct" -A 12 agent/statusclient/statusclient.go
```

Then, using the confirmed field names:

```go
func (r *resources) drawConnectionCard(hdc win.HDC, snap StatusSnapshot) {
	rc := dpiRect(24, 204, 428, 190)
	r.drawCard(hdc, rc)
	r.drawIconSignal(hdc, dpiXOnly(40)+24, dpiXOnly(20)+204, dpiXOnly(16), colMuted)
	r.drawText(hdc, "CONNECTION", dpiRect(60, 220, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	if !snap.Online {
		r.drawText(hdc, "Server: —", dpiRect(40, 248, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
		return
	}
	s := snap.Status
	rows := []struct{ label, value string }{
		{"Server", orDash(s.ServerURL)},
		{"Link", connLinkText(s)},
		{"Lifecycle State", orDash(s.State)},
		{"Uptime", formatUptime(s.UptimeSec)},
		{"Last Heartbeat", heartbeatText(s)},
	}
	y := 248
	for _, row := range rows {
		r.drawText(hdc, row.label, dpiRect(40, y, 160, 18), r.fontBody, colMuted, co.DT_LEFT)
		r.drawText(hdc, row.value, dpiRect(200, y, 236, 18), r.fontBody, colText, co.DT_RIGHT)
		y += 26
	}
}

func connLinkText(s statusclient.StatusResponse) string {
	switch {
	case s.ServerConnected:
		return "Connected"
	case s.Paused:
		return "Paused"
	default:
		return "Disconnected"
	}
}

func heartbeatText(s statusclient.StatusResponse) string {
	if s.LastHeartbeat == nil {
		return "—"
	}
	return s.LastHeartbeat.Format("15:04:05")
}

func (r *resources) drawOperationCard(hdc win.HDC, a statusclient.ActivityResponse) {
	rc := dpiRect(468, 204, 428, 190)
	r.drawCard(hdc, rc)
	r.drawIconClock(hdc, dpiXOnly(20)+468, dpiXOnly(20)+204, dpiXOnly(16), colMuted)
	r.drawText(hdc, "CURRENT OPERATION", dpiRect(504, 220, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	title, meta, result := "No active simulation", "Awaiting tasking from the BAS console", ""
	progress := 0
	switch {
	case a.CurrentOperation != nil && a.CurrentOperation.Running:
		op := a.CurrentOperation
		title = op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		meta = fmt.Sprintf("%d steps · phase: %s", op.TotalSteps, orDash(op.Phase))
		progress = op.Progress
	case a.LastOperation != nil:
		op := a.LastOperation
		title = op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		meta = fmt.Sprintf("Completed · %ds", op.DurationSec)
		progress = 100
		if op.Result != "" {
			result = "Result: " + op.Result
		}
	}
	r.drawText(hdc, title, dpiRect(484, 248, 380, 22), r.fontBody, colText, co.DT_LEFT)
	r.drawText(hdc, meta, dpiRect(484, 272, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
	r.drawProgressBar(hdc, dpiRect(484, 300, 380, 8), progress)
	if result != "" {
		r.drawText(hdc, result, dpiRect(484, 316, 380, 18), r.fontBody, colMuted, co.DT_LEFT)
	}
}
```

- [ ] **Step 4: Wire into `paint`**

```go
func (sw *windigoWindow) paint(hdc win.HDC) []buttonHitRect {
	sw.res.drawHeader(hdc, sw.latest)
	sw.res.drawHero(hdc, sw.latest)
	sw.res.drawConnectionCard(hdc, sw.latest)
	sw.res.drawOperationCard(hdc, sw.latest.Activity)
	return nil
}
```

- [ ] **Step 5: Build, cross-compile, screenshot-verify**

Same as Task 1 Step 6. Additionally verify the progress bar visually fills correctly by checking a snapshot with `CurrentOperation.Running=true, Progress=50` — if testing against a live idle agent, temporarily point `--status-window` at a small local `httptest`-style stub, or just confirm the 0% (idle) rendering looks right and trust `TestPollInterval_FastWhileRunning_SlowWhenIdle`'s existing coverage of the underlying data plumbing (unchanged in this task).

- [ ] **Step 6: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "feat(agent): owner-drawn connection + current operation cards"
```

---

## Task 4: Endpoint Security Controls card

**Files:**
- Modify: `agent/statuscanvas_windows.go`
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusclient.ControlsResponse.{Defender,Sysmon,Firewall,AppLocker,WDAC,AMSI}` and their sub-fields (`Defender.Present`, `Defender.RTPEnabled`, `Defender.TamperProtected`, `Sysmon.Present`, `Firewall.Enabled`, `AppLocker.Enabled`, `WDAC.Enabled`, `AMSI.Enabled` — confirm exact names via `grep -n "type ControlsResponse\|type DefenderCtrl\|type SysmonCtrl\|type FirewallCtrl\|type AppLockerCtrl\|type WDACCtrl\|type AMSICtrl" -A 6 agent/statusclient/statusclient.go` before writing).
- Produces: `func (r *resources) drawControlsCard(hdc win.HDC, c statusclient.ControlsResponse)`, `func (r *resources) drawStatusBadge(hdc win.HDC, rc win.RECT, label string, color win.COLORREF)` (reused by Task 5's Self-Protection card).

- [ ] **Step 1: Add the badge primitive**

```go
// drawStatusBadge paints a small pill: elevated-colored fill, 1px border
// and centered text both in the given status color (a GDI-native
// approximation of the browser dashboard's soft-tinted badges -- true
// alpha-tinted fills would need GDI+, explicitly out of scope).
func (r *resources) drawStatusBadge(hdc win.HDC, rc win.RECT, label string, color win.COLORREF) {
	hdc.SelectObjectBrush(r.brushElevated)
	pen, _ := win.CreatePen(co.PS_SOLID, 1, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	cx, cy := dpiPos(4, 4)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	r.drawText(hdc, label, rc, r.fontEyebrow, color, co.DT_CENTER)
}
```

- [ ] **Step 2: Add `drawControlsCard`**

```go
type controlRow struct {
	name, badge string
	color       win.COLORREF
}

func defenderRow(d statusclient.DefenderCtrl) controlRow {
	switch {
	case d.Present && d.RTPEnabled:
		return controlRow{"Defender RTP", "ACTIVE", colSuccess}
	case d.Present:
		return controlRow{"Defender RTP", "DEGRADED", colWarning}
	default:
		return controlRow{"Defender RTP", "ABSENT", colDanger}
	}
}

func boolRow(name string, on bool) controlRow {
	if on {
		return controlRow{name, "ACTIVE", colSuccess}
	}
	return controlRow{name, "ABSENT", colDanger}
}

func (r *resources) drawControlsCard(hdc win.HDC, c statusclient.ControlsResponse) {
	rc := dpiRect(24, 410, 872, 190)
	r.drawCard(hdc, rc)
	r.drawIconShield(hdc, dpiXOnly(44), dpiXOnly(430), dpiXOnly(16), colMuted)
	r.drawText(hdc, "ENDPOINT SECURITY CONTROLS", dpiRect(60, 426, 400, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	rows := []controlRow{
		defenderRow(c.Defender),
		boolRow("Sysmon", c.Sysmon.Present),
		boolRow("Firewall", c.Firewall.Enabled),
		boolRow("AppLocker", c.AppLocker.Enabled),
		boolRow("WDAC", c.WDAC.Enabled),
		boolRow("AMSI", c.AMSI.Enabled),
	}
	colX := []int{40, 468}
	for i, row := range rows {
		col := colX[i%2]
		y := 454 + (i/2)*44
		r.drawDot(hdc, col, y+2, 8, row.color)
		r.drawText(hdc, row.name, dpiRect(col+16, y, 200, 20), r.fontBody, colText, co.DT_LEFT)
		r.drawStatusBadge(hdc, dpiRect(col+240, y, 100, 24), row.badge, row.color)
	}
}
```

- [ ] **Step 3: Wire into `paint`**

```go
sw.res.drawControlsCard(hdc, sw.latest.Controls)
```

(add this line after `drawOperationCard` in `windigoWindow.paint`)

- [ ] **Step 4: Build, cross-compile, screenshot-verify**

Same as Task 1 Step 6. Confirm all 6 rows render in a 2-column × 3-row grid with correctly colored dots and badges matching whatever real Defender/Firewall/AMSI/etc. state the test machine reports (compare against the live browser dashboard screenshot of the same agent, taken earlier this session, as a sanity cross-check).

- [ ] **Step 5: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "feat(agent): owner-drawn endpoint security controls card"
```

---

## Task 5: Evidence + Self-Protection cards

**Files:**
- Modify: `agent/statuscanvas_windows.go`
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusclient.EvidenceResponse.{EventsCollected,DefenderAlerts,SysmonDetections,QueueSize}`, `statusclient.StatusResponse.{ServiceRunning,State,LastUploadOk,ServerConnected}` (confirm exact names via `grep -n "type EvidenceResponse" -A 6 agent/statusclient/statusclient.go`).
- Produces: `func (r *resources) drawEvidenceCard(hdc win.HDC, ev statusclient.EvidenceResponse)`, `func (r *resources) drawSelfProtectionCard(hdc win.HDC, s statusclient.StatusResponse, ev statusclient.EvidenceResponse)`, `func (r *resources) drawIconCheckBadge(...)`, `func (r *resources) drawIconPin(...)`, `func (r *resources) drawStatTile(hdc win.HDC, rc win.RECT, value string, label string)` (reused by Task 6's Resources card).

- [ ] **Step 1: Add check-badge and pin icon glyphs, plus the stat-tile primitive**

```go
func (r *resources) drawIconCheckBadge(hdc win.HDC, x, y, size int, color win.COLORREF) {
	pen, _ := win.CreatePen(co.PS_SOLID, 2, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	hdc.SelectObjectBrush(r.brushCard)
	hdc.Ellipse(win.RECT{Left: int32(x), Top: int32(y), Right: int32(x + size), Bottom: int32(y + size)})
	hdc.MoveToEx(x+size/4, y+size/2)
	hdc.LineTo(x+size*2/5, y+size*3/4)
	hdc.LineTo(x+size*3/4, y+size/4)
}

func (r *resources) drawIconPin(hdc win.HDC, x, y, size int, color win.COLORREF) {
	pen, _ := win.CreatePen(co.PS_SOLID, 2, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	hdc.SelectObjectBrush(r.brushCard)
	pts := []win.POINT{
		{X: int32(x + size/2), Y: int32(y + size)},
		{X: int32(x), Y: int32(y + size/3)},
		{X: int32(x + size/4), Y: int32(y)},
		{X: int32(x + size*3/4), Y: int32(y)},
		{X: int32(x + size), Y: int32(y + size/3)},
	}
	hdc.Polygon(pts)
}

// drawStatTile paints an elevated-surface tile with a large value and a
// small muted caption below it -- used by Evidence, Resources, and any
// future numeric-summary card.
func (r *resources) drawStatTile(hdc win.HDC, rc win.RECT, value, label string) {
	hdc.SelectObjectBrush(r.brushElevated)
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(6, 6)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	valueRc := rc
	valueRc.Bottom -= (rc.Bottom - rc.Top) / 3
	r.drawText(hdc, value, valueRc, r.fontHeading, colText, co.DT_LEFT)
	labelRc := rc
	labelRc.Top = valueRc.Bottom
	r.drawText(hdc, label, labelRc, r.fontEyebrow, colMuted, co.DT_LEFT)
}
```

- [ ] **Step 2: Add `drawEvidenceCard` and `drawSelfProtectionCard`**

```go
func (r *resources) drawEvidenceCard(hdc win.HDC, ev statusclient.EvidenceResponse) {
	rc := dpiRect(24, 616, 428, 210)
	r.drawCard(hdc, rc)
	r.drawIconCheckBadge(hdc, dpiXOnly(44), dpiXOnly(636), dpiXOnly(16), colMuted)
	r.drawText(hdc, "EVIDENCE · LAST RUN", dpiRect(60, 632, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	tiles := []struct{ value, label string }{
		{fmt.Sprintf("%d", ev.EventsCollected), "EVENTS COLLECTED"},
		{fmt.Sprintf("%d", ev.DefenderAlerts), "DEFENDER ALERTS"},
		{fmt.Sprintf("%d", ev.SysmonDetections), "SYSMON DETECTIONS"},
		{fmt.Sprintf("%d", ev.QueueSize), "UPLOAD QUEUE"},
	}
	tileW, tileH, gap := 186, 64, 12
	for i, t := range tiles {
		col, row := i%2, i/2
		x := 40 + col*(tileW+gap)
		y := 660 + row*(tileH+gap)
		r.drawStatTile(hdc, dpiRect(x, y, tileW, tileH), t.value, t.label)
	}
}

func (r *resources) drawSelfProtectionCard(hdc win.HDC, s statusclient.StatusResponse, ev statusclient.EvidenceResponse) {
	rc := dpiRect(468, 616, 428, 210)
	r.drawCard(hdc, rc)
	r.drawIconPin(hdc, dpiXOnly(488), dpiXOnly(636), dpiXOnly(16), colMuted)
	r.drawText(hdc, "SELF-PROTECTION", dpiRect(504, 632, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	rows := []controlRow{
		healthRow("Service Running", s.ServiceRunning),
		healthRow("Policy Sync", s.State == "active" || s.State == "restricted"),
		healthRow("Evidence Queue", ev.QueueSize < 100),
		healthRow("Last Upload OK", s.LastUploadOk),
		healthRow("Server Contact", s.ServerConnected),
	}
	y := 660
	for _, row := range rows {
		r.drawDot(hdc, 484, y+2, 8, row.color)
		r.drawText(hdc, row.name, dpiRect(500, y, 220, 20), r.fontBody, colText, co.DT_LEFT)
		r.drawStatusBadge(hdc, dpiRect(756, y, 100, 24), row.badge, row.color)
		y += 28
	}
}

func healthRow(name string, healthy bool) controlRow {
	if healthy {
		return controlRow{name, "HEALTHY", colSuccess}
	}
	return controlRow{name, "CHECK", colWarning}
}
```

- [ ] **Step 3: Wire into `paint`**

```go
sw.res.drawEvidenceCard(hdc, sw.latest.Evidence)
sw.res.drawSelfProtectionCard(hdc, sw.latest.Status, sw.latest.Evidence)
```

(after `drawControlsCard`)

- [ ] **Step 4: Build, cross-compile, screenshot-verify**

Same as Task 1 Step 6.

- [ ] **Step 5: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "feat(agent): owner-drawn evidence + self-protection cards"
```

---

## Task 6: Resources card

**Files:**
- Modify: `agent/statuscanvas_windows.go`
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusclient.StatusResponse.{RamMB,AgentVersion,AgentID}`, `resources.drawStatTile` (Task 5).
- Produces: `func (r *resources) drawResourcesCard(hdc win.HDC, s statusclient.StatusResponse)`, `func (r *resources) drawIconMonitor(hdc win.HDC, x, y, size int, color win.COLORREF)`.

- [ ] **Step 1: Add monitor icon glyph**

```go
func (r *resources) drawIconMonitor(hdc win.HDC, x, y, size int, color win.COLORREF) {
	pen, _ := win.CreatePen(co.PS_SOLID, 2, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	hdc.SelectObjectBrush(r.brushCard)
	screenH := size * 2 / 3
	hdc.RoundRect(win.RECT{Left: int32(x), Top: int32(y), Right: int32(x + size), Bottom: int32(y + screenH)}, win.SIZE{Cx: 3, Cy: 3})
	standX := x + size/2
	hdc.MoveToEx(standX, y+screenH)
	hdc.LineTo(standX, y+size)
	hdc.MoveToEx(x+size/4, y+size)
	hdc.LineTo(x+size*3/4, y+size)
}
```

- [ ] **Step 2: Add `drawResourcesCard`**

```go
func (r *resources) drawResourcesCard(hdc win.HDC, s statusclient.StatusResponse) {
	rc := dpiRect(24, 842, 872, 130)
	r.drawCard(hdc, rc)
	r.drawIconMonitor(hdc, dpiXOnly(44), dpiXOnly(862), dpiXOnly(16), colMuted)
	r.drawText(hdc, "RESOURCES", dpiRect(60, 858, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	tiles := []struct{ value, label string }{
		{fmt.Sprintf("%d MB", s.RamMB), "MEMORY (WORKING SET)"},
		{"v" + s.AgentVersion, "AGENT VERSION"},
		{orDash(s.AgentID), "AGENT ID"},
	}
	tileW, tileH, gap := 272, 64, 16
	for i, t := range tiles {
		x := 40 + i*(tileW+gap)
		r.drawStatTile(hdc, dpiRect(x, 886, tileW, tileH), t.value, t.label)
	}
}
```

- [ ] **Step 3: Wire into `paint`**

```go
sw.res.drawResourcesCard(hdc, sw.latest.Status)
```

- [ ] **Step 4: Build, cross-compile, screenshot-verify**

Same as Task 1 Step 6.

- [ ] **Step 5: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "feat(agent): owner-drawn resources card"
```

---

## Task 7: Recent Activity card

**Files:**
- Modify: `agent/statuscanvas_windows.go`
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `statusclient.Activity.{Time,Event}` (`statusclient.ActivityResponse.RecentActivity []statusclient.Activity`, confirm exact field name via `grep -n "type Activity struct\|RecentActivity" agent/statusclient/statusclient.go`).
- Produces: `func (r *resources) drawActivityCard(hdc win.HDC, items []statusclient.Activity)`, `func (r *resources) drawIconPulse(hdc win.HDC, x, y, size int, color win.COLORREF)`.

- [ ] **Step 1: Add pulse icon glyph**

```go
func (r *resources) drawIconPulse(hdc win.HDC, x, y, size int, color win.COLORREF) {
	pen, _ := win.CreatePen(co.PS_SOLID, 2, color)
	defer pen.DeleteObject()
	hdc.SelectObjectPen(pen)
	pts := []win.POINT{
		{X: int32(x), Y: int32(y + size/2)},
		{X: int32(x + size/3), Y: int32(y + size/2)},
		{X: int32(x + size/2), Y: int32(y)},
		{X: int32(x + size*2/3), Y: int32(y + size)},
		{X: int32(x + size), Y: int32(y + size/2)},
	}
	hdc.Polyline(pts)
}
```

- [ ] **Step 2: Add `drawActivityCard`**

Fixed 8 visible rows (no scrolling, per spec's approved "tall fixed window" decision) — shows the 8 most recent entries, newest first (matching the existing data ordering already produced server-side, unchanged by this task):

```go
func (r *resources) drawActivityCard(hdc win.HDC, items []statusclient.Activity) {
	rc := dpiRect(24, 988, 872, 240)
	r.drawCard(hdc, rc)
	r.drawIconPulse(hdc, dpiXOnly(44), dpiXOnly(1008), dpiXOnly(16), colMuted)
	r.drawText(hdc, "RECENT ACTIVITY", dpiRect(60, 1004, 300, 16), r.fontEyebrow, colMuted, co.DT_LEFT)

	if len(items) == 0 {
		r.drawText(hdc, "No recent activity recorded.", dpiRect(40, 1032, 800, 18), r.fontBody, colMuted, co.DT_LEFT)
		return
	}
	max := len(items)
	if max > 8 {
		max = 8
	}
	y := 1032
	for _, item := range items[:max] {
		r.drawDot(hdc, 40, y+5, 6, colAccent)
		r.drawText(hdc, item.Time.Format("15:04:05"), dpiRect(56, y, 80, 18), r.fontBody, colMuted, co.DT_LEFT)
		r.drawText(hdc, item.Event, dpiRect(148, y, 720, 18), r.fontBody, colText, co.DT_LEFT)
		y += 22
	}
}
```

- [ ] **Step 3: Wire into `paint`, finishing the method**

```go
func (sw *windigoWindow) paint(hdc win.HDC) []buttonHitRect {
	sw.res.drawHeader(hdc, sw.latest)
	sw.res.drawHero(hdc, sw.latest)
	sw.res.drawConnectionCard(hdc, sw.latest)
	sw.res.drawOperationCard(hdc, sw.latest.Activity)
	sw.res.drawControlsCard(hdc, sw.latest.Controls)
	sw.res.drawEvidenceCard(hdc, sw.latest.Evidence)
	sw.res.drawSelfProtectionCard(hdc, sw.latest.Status, sw.latest.Evidence)
	sw.res.drawResourcesCard(hdc, sw.latest.Status)
	sw.res.drawActivityCard(hdc, sw.latest.Activity.RecentActivity)
	return sw.drawActionRow(hdc) // Task 8
}
```

(the call to `sw.drawActionRow` is added here now but implemented in Task 8 — until Task 8 lands, comment this line out or stub `drawActionRow` to return `nil` so the build stays green; prefer stubbing since leaving commented-out code is worse than a one-line stub)

Add the stub to `agent/statuswindow_windows.go` for this task:

```go
func (sw *windigoWindow) drawActionRow(hdc win.HDC) []buttonHitRect {
	return nil
}
```

- [ ] **Step 4: Build, cross-compile, screenshot-verify**

Same as Task 1 Step 6. Confirm the activity feed shows real recent entries (e.g. repeated "Heartbeat OK" rows as seen in the browser dashboard reference screenshot) in the correct order with correct timestamps.

- [ ] **Step 5: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "feat(agent): owner-drawn recent activity card"
```

---

## Task 8: Owner-drawn action buttons + click handling

**Files:**
- Modify: `agent/statuscanvas_windows.go`
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `windigoWindow.controller.ExportDiagnostics()`, `windigoWindow.controller.OpenDashboard(serverURL string)` (unchanged from `agent/statuscontroller.go`), `buttonHitRect` (Task 1).
- Produces: `func (r *resources) drawButton(hdc win.HDC, rc win.RECT, label string, primary bool) win.RECT` (returns the rect for hit-testing), replaces `drawActionRow`'s Task 7 stub.

- [ ] **Step 1: Add the button primitive**

```go
// drawButton paints a rounded rect button: accent-filled for primary,
// elevated-filled with a border for secondary. Returns rc unchanged so
// callers can pass it straight into a buttonHitRect.
func (r *resources) drawButton(hdc win.HDC, rc win.RECT, label string, primary bool) win.RECT {
	if primary {
		hdc.SelectObjectBrush(r.brushAccent)
	} else {
		hdc.SelectObjectBrush(r.brushElevated)
	}
	hdc.SelectObjectPen(r.penBorder)
	cx, cy := dpiPos(6, 6)
	hdc.RoundRect(rc, win.SIZE{Cx: int32(cx), Cy: int32(cy)})
	r.drawText(hdc, label, rc, r.fontBody, colText, co.DT_CENTER)
	return rc
}
```

- [ ] **Step 2: Replace the Task 7 stub with the real `drawActionRow` in `agent/statuswindow_windows.go`**

```go
func (sw *windigoWindow) drawActionRow(hdc win.HDC) []buttonHitRect {
	exportRc := dpiRect(24, 1244, 220, 36)
	dashRc := dpiRect(260, 1244, 180, 36)

	sw.res.drawButton(hdc, exportRc, "Export Diagnostic Bundle", false)
	sw.res.drawButton(hdc, dashRc, "Open BAS Console", true)

	updated := "Updated " + time.Now().Format("15:04:05")
	sw.res.drawText(hdc, updated, dpiRect(696, 1250, 176, 20), sw.res.fontBody, colMuted, co.DT_RIGHT)

	serverURL := sw.latest.Status.ServerURL
	return []buttonHitRect{
		{rc: exportRc, onClick: func() {
			if sw.controller != nil {
				sw.controller.ExportDiagnostics()
			}
		}},
		{rc: dashRc, onClick: func() {
			if sw.controller != nil {
				sw.controller.OpenDashboard(serverURL)
			}
		}},
	}
}
```

Add `"time"` to `agent/statuswindow_windows.go`'s imports if not already present.

- [ ] **Step 3: Build, cross-compile, screenshot-verify, and click-test**

Same build/cross-compile commands as Task 1 Step 6. For the click test: since automated clicking wasn't part of this session's established verification toolkit, use the `mcp__claude-in-chrome__computer` tool's approach is not applicable to a native window — instead use a PowerShell `SendMessage`/`SetCursorPos`+`mouse_event` simulated click at the button's known screen coordinates (derived from `GetWindowRect` + the button's client-relative rect logged via a temporary debug print), or ask the user to manually click both buttons once and confirm "Export Diagnostic Bundle" produces a file and "Open BAS Console" opens the browser. Record which verification path was actually used.

- [ ] **Step 4: Commit**

```bash
git add agent/statuscanvas_windows.go agent/statuswindow_windows.go
git commit -m "feat(agent): owner-drawn action buttons with click hit-testing

Completes the visual redesign -- every panel from the original stock-
control window (Tasks 4-7 of 2026-08-07-native-status-console.md) is
now owner-drawn GDI matching the browser dashboard's dark card design."
```

---

## Task 9: Final full-suite verification pass

**Files:** none (verification only)

- [ ] **Step 1: Full build/vet/test/cross-compile**

```bash
cd agent
go build ./...
go vet ./...
go test ./... -v
GOOS=linux go build ./...
GOOS=darwin go build ./...
```

Expected: all green, including the untouched `statusclient_test.go`/`statuscontroller_test.go` suites and the rest of the agent's pre-existing test suite (`TestStopSelf_*`, `TestUninstallSelf_*`, etc.).

- [ ] **Step 2: Live screenshot pass against a real agent**

Same `PrintWindow`-based technique used throughout this plan and the original native-console session. Run `bas_agent_test.exe --status-window` against either a fresh test agent or (read-only, non-destructively, as already established this session) the real installed `BASAgent` service, and capture the full window.

- [ ] **Step 3: Compare against the browser dashboard reference**

Open `http://127.0.0.1:9001/?t=<token>` in Chrome side-by-side with the native screenshot (same technique used earlier this session) and visually confirm: same section order, same data, colors read as the same semantic meaning (green=healthy, red=absent/disconnected, amber=check/degraded), no clipped text, no overlapping elements.

- [ ] **Step 4: Report to user**

Summarize what was verified, attach or describe the final screenshot, and note any remaining gaps (e.g. DPI-scaling variations, dark/light OS theme — now moot per this plan's design since the window no longer inherits OS theme — RDP session behavior) the same way Task 9 of the original native-console plan handled items that needed the user's own hands-on check.

No commit for this task (verification only) unless Step 2/3 surface a bug, in which case fix it, verify again, and commit the fix with a message explaining what was found (matching this session's established pattern for the width-clipping fix in the original plan).
