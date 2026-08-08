//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
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
	// A Win32 window's message queue is bound to the specific OS thread
	// that created it -- GetMessage must keep being called from that same
	// thread for the window's entire lifetime. Without this, Go's
	// scheduler is free to migrate this goroutine to a different OS thread
	// at any preemption point; if that ever happens mid-message-loop, every
	// later GetMessage call polls the wrong thread's (empty) queue and the
	// window silently stops responding to everything -- clicks, scroll,
	// close -- while the process itself stays alive. This was missing here
	// (present only for the tray window, runTray in tray_windows.go) and is
	// the most likely explanation for AppHang reports on this window that
	// predate this fix and were reproducible under real interactive use
	// but never under short synthetic input tests.
	runtime.LockOSThread()

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

// Raw syscalls for the handful of Win32 calls windigo doesn't wrap:
// SetWindowOrgEx (owner-drawn scrolling, statuscanvas has no scrollbar
// control to delegate to), ExtractIconExW + WM_SETICON (the window's own
// taskbar/title-bar icon -- windigo's ClassIconId needs a numeric resource
// ID we don't reliably know since rsrc.exe assigns it, so we extract by
// position from the running exe instead, same technique Explorer itself
// uses to show a file's icon).
var (
	modGdi32   = windows.NewLazySystemDLL("gdi32.dll")
	modUser32  = windows.NewLazySystemDLL("user32.dll")
	modShell32 = windows.NewLazySystemDLL("shell32.dll")

	procSetWindowOrgEx = modGdi32.NewProc("SetWindowOrgEx")
	procSendMessageW   = modUser32.NewProc("SendMessageW")
	procExtractIconExW = modShell32.NewProc("ExtractIconExW")
)

func setWindowOrgEx(hdc win.HDC, x, y int32) {
	procSetWindowOrgEx.Call(uintptr(hdc), uintptr(x), uintptr(y), 0)
}

const (
	wmSetIcon = 0x0080
	iconSmall = 0
	iconBig   = 1
)

func setWindowIcon(hwnd win.HWND, hIconBig, hIconSmall uintptr) {
	if hIconBig != 0 {
		procSendMessageW.Call(uintptr(hwnd), wmSetIcon, iconBig, hIconBig)
	}
	if hIconSmall != 0 {
		procSendMessageW.Call(uintptr(hwnd), wmSetIcon, iconSmall, hIconSmall)
	}
}

// loadAppIcons extracts the running executable's own icon (index 0 --
// whatever icon rsrc.exe embedded at build time, by position rather than
// by a specific resource ID/name we'd otherwise have to guess) at both
// large and small sizes, for the title bar and taskbar respectively.
func loadAppIcons() (large, small uintptr) {
	exePath, err := os.Executable()
	if err != nil {
		return 0, 0
	}
	pathPtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return 0, 0
	}
	var hLarge, hSmall uintptr
	ret, _, _ := procExtractIconExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0, // icon index -- first icon in the exe
		uintptr(unsafe.Pointer(&hLarge)),
		uintptr(unsafe.Pointer(&hSmall)),
		1,
	)
	if ret == 0 {
		return 0, 0
	}
	return hLarge, hSmall
}

func revealInExplorer(path string) {
	cmd := exec.Command("explorer.exe", "/select,"+path)
	_ = cmd.Start()
}

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

	// scrollY is the vertical scroll offset in device pixels (0 = top of
	// content). contentHeight is the full design content height, scaled --
	// on any display shorter than that, the window can't show everything
	// at once (see clampToWorkArea's doc comment), so mouse-wheel scrolling
	// is the only way to reach content below the fold.
	scrollY       int32
	contentHeight int32

	// targetScrollY is where an in-progress wheel-driven scroll animation
	// is easing toward; scrollY is the current, already-rendered position.
	// A raw per-notch jump (the previous behavior: scrollY set directly,
	// one repaint per notch) is not what "smooth scrolling" means -- real
	// smoothness needs animated interpolation across several frames, which
	// is what the WM_TIMER handler below does.
	targetScrollY int32
	scrollAnim    bool

	// Off-screen back buffer for double-buffered painting -- reused across
	// paints and only recreated when the client size actually changes, so
	// repeated WM_PAINT calls (e.g. one per mouse-wheel notch while
	// scrolling) don't allocate/free a GDI bitmap every frame.
	bufDC     win.HDC
	bufBmp    win.HBITMAP
	bufOldBmp win.HBITMAP
	bufW      int32
	bufH      int32
}

// ensureBackBuffer (re)creates the cached off-screen buffer only when the
// client size differs from what's cached -- a no-op on every paint except
// the first and after a real resize.
func (sw *windigoWindow) ensureBackBuffer(hdc win.HDC, w, h int32) {
	if sw.bufDC != 0 && sw.bufW == w && sw.bufH == h {
		return
	}
	sw.releaseBackBuffer()
	if w <= 0 || h <= 0 {
		return
	}
	memDC, err := hdc.CreateCompatibleDC()
	if err != nil {
		return
	}
	bmp, err := hdc.CreateCompatibleBitmap(int(w), int(h))
	if err != nil {
		memDC.DeleteDC()
		return
	}
	oldBmp, _ := memDC.SelectObjectBmp(bmp)
	sw.bufDC = memDC
	sw.bufBmp = bmp
	sw.bufOldBmp = oldBmp
	sw.bufW, sw.bufH = w, h
}

// releaseBackBuffer deselects the buffer bitmap before deleting it (so we
// never delete a GDI object while it's still selected into a DC) and tears
// the whole thing down -- called before recreating at a new size and once
// more at WM_DESTROY.
func (sw *windigoWindow) releaseBackBuffer() {
	if sw.bufDC != 0 && sw.bufOldBmp != 0 {
		sw.bufDC.SelectObjectBmp(sw.bufOldBmp)
	}
	if sw.bufBmp != 0 {
		sw.bufBmp.DeleteObject()
		sw.bufBmp = 0
	}
	if sw.bufDC != 0 {
		sw.bufDC.DeleteDC()
		sw.bufDC = 0
	}
	sw.bufOldBmp = 0
	sw.bufW, sw.bufH = 0, 0
}

func newWindigoWindow() *windigoWindow {
	sw := &windigoWindow{res: newResources()}

	cx, cy := ui.Dpi(920, 1320)
	sw.contentHeight = int32(cy)
	sw.wnd = ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent").
			Size(cx, cy).
			ClassBrush(sw.res.brushBg).
			ClassStyle(co.CS_HREDRAW | co.CS_VREDRAW).
			// A real scrollbar (thumb drag/click handled largely by USER32
			// itself via WM_VSCROLL, not a custom per-notch handler) is the
			// industry-standard technique for this scenario, including over
			// RDP. Explicit style list because setting Style() replaces
			// windigo's whole default
			// (WS_CAPTION|WS_SYSMENU|WS_CLIPCHILDREN|WS_BORDER|WS_VISIBLE|
			// WS_MINIMIZEBOX), not just adds to it.
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_CLIPCHILDREN|co.WS_BORDER|co.WS_VISIBLE|co.WS_MINIMIZEBOX|co.WS_VSCROLL),
			// WS_EX_COMPOSITED was tried here and made no real difference --
			// it mainly eliminates flicker between *child windows/controls*
			// compositing together, and this console has none: everything
			// is owner-drawn directly onto this one window's client area in
			// a single WM_PAINT. That's a true double-buffering scenario
			// (draw off-screen, one BitBlt to screen), handled below via
			// the cached back buffer instead.
	)

	sw.wnd.On().WmCreate(func(p ui.WmCreate) int {
		sw.wnd.Hwnd().DwmSetWindowAttribute(win.DwmAttrUseImmersiveDarkMode(true))
		sw.clampToWorkArea()
		if big, small := loadAppIcons(); big != 0 || small != 0 {
			setWindowIcon(sw.wnd.Hwnd(), big, small)
		}
		sw.updateScrollInfo()
		return 0
	})

	sw.wnd.On().WmVScroll(func(p ui.WmScroll) {
		clientRc, _ := sw.wnd.Hwnd().GetClientRect()
		clientH := clientRc.Bottom - clientRc.Top
		step := int32(dpiXOnly(60))
		switch p.Request() {
		case co.SB_REQ_LINEUP:
			sw.setScrollY(sw.scrollY - step)
		case co.SB_REQ_LINEDOWN:
			sw.setScrollY(sw.scrollY + step)
		case co.SB_REQ_PAGEUP:
			sw.setScrollY(sw.scrollY - clientH)
		case co.SB_REQ_PAGEDOWN:
			sw.setScrollY(sw.scrollY + clientH)
		case co.SB_REQ_THUMBTRACK, co.SB_REQ_THUMBPOSITION:
			sw.setScrollY(int32(p.ScrollBoxPos()))
		case co.SB_REQ_TOP:
			sw.setScrollY(0)
		case co.SB_REQ_BOTTOM:
			sw.setScrollY(sw.contentHeight)
		}
	})

	// WM_MOUSEWHEEL (0x020A) has no typed windigo wrapper, so it's
	// registered via the generic Wm() escape hatch. Kept alongside the
	// scrollbar (not removed) since a build with this handler entirely
	// absent still hung under real use -- this was never proven to be the
	// actual cause, just the most recent thing changed before each hang
	// report.
	//
	// Eased via scrollAnimTimer instead of jumping scrollY directly: a
	// direct jump-and-repaint per notch is flicker-free (thanks to the back
	// buffer) but still reads as "not smooth" -- real smooth scrolling is
	// animated motion across several frames, not an artifact-free instant
	// jump.
	sw.wnd.On().Wm(co.WM(0x020A), func(p ui.Wm) uintptr {
		delta := int32(int16(uint16(uint32(p.WParam) >> 16)))
		step := int32(dpiXOnly(60))
		sw.startScrollAnim(sw.targetScrollY - (delta/120)*step)
		return 0
	})

	sw.wnd.On().WmTimer(scrollAnimTimerID, func() {
		sw.stepScrollAnim()
	})

	// Windows' default WM_GETMINMAXINFO handling can cap a top-level
	// window's settable size to the monitor's work area during interactive
	// resize/SetWindowPos, independent of resizability. Our tall
	// fixed-content window (no scrolling, per design) is legitimately
	// taller than many real screens' work areas, so we widen the
	// track-size ceiling well past anything we'll ever request. This is a
	// standard defensive measure; it did not by itself resolve the
	// separate window-height cap observed on this session's build VM
	// (see docs/superpowers/plans/2026-08-07-native-console-visual-redesign.md
	// Task 1 notes) -- that cap turned out to be a lower-level constraint
	// of this VM's virtual display, unrelated to WM_GETMINMAXINFO.
	sw.wnd.On().WmGetMinMaxInfo(func(p ui.WmGetMinMaxInfo) {
		info := p.Info()
		info.PtMaxTrackSize.X = 4000
		info.PtMaxTrackSize.Y = 4000
	})

	sw.wnd.On().WmEraseBkgnd(func(p ui.WmEraseBkgnd) int {
		return 1 // we paint the whole background ourselves in WmPaint
	})

	sw.wnd.On().WmPaint(func() {
		var ps win.PAINTSTRUCT
		hdc, _ := sw.wnd.Hwnd().BeginPaint(&ps)
		defer sw.wnd.Hwnd().EndPaint(&ps)

		clientRc, _ := sw.wnd.Hwnd().GetClientRect()
		w, h := clientRc.Right-clientRc.Left, clientRc.Bottom-clientRc.Top
		sw.ensureBackBuffer(hdc, w, h)

		// Draw the full frame off-screen first, then blit it to the screen
		// in one copy -- painting ~10 cards' worth of GDI calls directly
		// onto the visible surface (the previous approach) is what produced
		// the visible flicker during scrolling.
		target := sw.bufDC
		if target == 0 {
			target = hdc // back buffer alloc failed -- fall back to direct paint
		}

		target.FillRect(&win.RECT{Left: 0, Top: 0, Right: w, Bottom: h}, sw.res.brushBg)

		// Shift the DC's logical origin down by the scroll offset so every
		// existing drawXxx call (all written in fixed content-space
		// coordinates) renders shifted without needing to thread scrollY
		// through each one individually. windigo doesn't wrap
		// SetWindowOrgEx, hence the raw syscall above.
		setWindowOrgEx(target, 0, sw.scrollY)
		sw.buttons = sw.paint(target)

		if target != hdc {
			setWindowOrgEx(target, 0, 0) // back to device coords for the blit below
			hdc.BitBlt(win.POINT{X: 0, Y: 0}, win.SIZE{Cx: w, Cy: h}, target, win.POINT{X: 0, Y: 0}, co.ROP_SRCCOPY)
		}
	})

	sw.wnd.On().WmLButtonUp(func(p ui.WmMouse) {
		pt := p.Pos()
		// Click coordinates arrive in client (device) space; button rects
		// were recorded in content (logical/scrolled) space during paint,
		// so translate the click the same way WM_PAINT translates drawing.
		contentY := int32(pt.Y) + sw.scrollY
		for _, b := range sw.buttons {
			if int32(pt.X) >= b.rc.Left && int32(pt.X) <= b.rc.Right &&
				contentY >= b.rc.Top && contentY <= b.rc.Bottom {
				b.onClick()
				return
			}
		}
	})

	sw.wnd.On().WmDestroy(func() {
		if sw.scrollAnim {
			sw.wnd.Hwnd().KillTimer(scrollAnimTimerID)
		}
		sw.releaseBackBuffer()
		sw.res.release()
	})

	return sw
}

// maxScroll returns how far scrollY can go before the bottom of the content
// lines up with the bottom of the client area.
func (sw *windigoWindow) maxScroll() int32 {
	clientRc, _ := sw.wnd.Hwnd().GetClientRect()
	m := sw.contentHeight - (clientRc.Bottom - clientRc.Top)
	if m < 0 {
		m = 0
	}
	return m
}

// scrollAnimTimerID is the WM_TIMER id used for the eased wheel-scroll
// animation (see startScrollAnim/stepScrollAnim). Only one timer is ever
// active on this window, so a fixed id is fine.
const scrollAnimTimerID = 1

// startScrollAnim sets a new target for the eased wheel-scroll animation
// and starts the timer if it isn't already running. A wheel notch that
// arrives while an animation is already in flight accumulates onto the
// current target -- targetScrollY tracks scrollY exactly whenever no
// animation is running (stepScrollAnim snaps them equal on completion), so
// reading it as the base here is always the right starting point, whether
// or not an animation happens to be active.
func (sw *windigoWindow) startScrollAnim(target int32) {
	max := sw.maxScroll()
	if target < 0 {
		target = 0
	}
	if target > max {
		target = max
	}
	sw.targetScrollY = target
	if !sw.scrollAnim {
		sw.scrollAnim = true
		sw.wnd.Hwnd().SetTimer(scrollAnimTimerID, 16) // ~60fps
	}
}

// stepScrollAnim eases scrollY a fraction of the remaining distance toward
// targetScrollY on every timer tick, producing a decelerating glide instead
// of an instant per-notch jump. Stops itself once close enough that the
// remainder would never visibly settle (integer division of a distance
// under 3 truncates to 0, which would tick forever without converging).
func (sw *windigoWindow) stepScrollAnim() {
	diff := sw.targetScrollY - sw.scrollY
	if diff > -3 && diff < 3 {
		sw.scrollY = sw.targetScrollY
		sw.wnd.Hwnd().KillTimer(scrollAnimTimerID)
		sw.scrollAnim = false
	} else {
		sw.scrollY += diff / 3
	}
	sw.updateScrollInfo()
	sw.wnd.Hwnd().InvalidateRect(nil, false)
}

// setScrollY clamps y to [0, maxScroll], applies it immediately (no
// easing -- used by direct scrollbar interaction, where the thumb should
// track the mouse 1:1), updates the real scrollbar thumb/range to match
// (SetScrollInfo, not just cosmetic -- without this the thumb would
// silently drift out of sync with what's actually drawn), and repaints.
// Also cancels any in-flight wheel-scroll animation so the two mechanisms
// can't fight over scrollY (e.g. wheel-scroll then immediately grab the
// scrollbar thumb).
func (sw *windigoWindow) setScrollY(y int32) {
	if sw.scrollAnim {
		sw.wnd.Hwnd().KillTimer(scrollAnimTimerID)
		sw.scrollAnim = false
	}
	max := sw.maxScroll()
	if y < 0 {
		y = 0
	}
	if y > max {
		y = max
	}
	sw.scrollY = y
	sw.targetScrollY = y
	sw.updateScrollInfo()
	sw.wnd.Hwnd().InvalidateRect(nil, false)
}

// updateScrollInfo pushes contentHeight/client-height/scrollY into the
// window's real scrollbar (range, page size, thumb position) via
// SetScrollInfo. Called at creation and after every scrollY change so the
// scrollbar always reflects what's actually drawn.
func (sw *windigoWindow) updateScrollInfo() {
	clientRc, _ := sw.wnd.Hwnd().GetClientRect()
	var si win.SCROLLINFO
	si.SetCbSize()
	si.Mask = co.SIF_RANGE | co.SIF_PAGE | co.SIF_POS | co.SIF_DISABLENOSCROLL
	si.Min = 0
	si.Max = sw.contentHeight
	si.Page = uint32(clientRc.Bottom - clientRc.Top)
	si.Pos = sw.scrollY
	sw.wnd.Hwnd().SetScrollInfo(co.SBB_VERT, &si, true)
}

// clampToWorkArea repositions the window so its top edge never lands above
// the visible work area. windigo centers new windows purely from screen
// dimensions (SM_CXSCREEN/CYSCREEN) with no clamping, so on any display
// whose usable height is shorter than our fixed content height, the window
// ends up with a negative Top -- part of it (including the header and hero
// card) renders entirely off-screen with no way for the user to scroll or
// drag it into view (found live: a real window on this session's build VM
// centered to Top=-330). Top-aligning instead of vertically centering means
// the most important content is always visible even when the whole window
// can't fit on a shorter screen.
func (sw *windigoWindow) clampToWorkArea() {
	var workRect win.RECT
	if err := win.SystemParametersInfo(co.SPI_GETWORKAREA, 0, unsafe.Pointer(&workRect), 0); err != nil {
		return
	}
	rc, err := sw.wnd.Hwnd().GetWindowRect()
	if err != nil {
		return
	}
	if rc.Top >= workRect.Top {
		return // already fully on-screen (or at least not clipped above)
	}
	sw.wnd.Hwnd().SetWindowPos(win.HWND(0), win.POINT{X: rc.Left, Y: workRect.Top},
		win.SIZE{}, co.SWP_NOSIZE|co.SWP_NOZORDER|co.SWP_NOACTIVATE)
}

// dpiPos is a small local wrapper around ui.Dpi so every coordinate call
// site in this file and statuscanvas_windows.go can pass a single (x,y)
// pair without repeating the two-return-value ui.Dpi(x,y) call inline
// everywhere.
func dpiPos(x, y int) (int, int) { return ui.Dpi(x, y) }

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

// paint draws the full frame from sw.latest and returns the current
// button hit-rects (recomputed every paint since layout is static).
// Later tasks extend this method section by section; this task only
// establishes the empty dark canvas.
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
	return sw.drawActionRow(hdc)
}

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
