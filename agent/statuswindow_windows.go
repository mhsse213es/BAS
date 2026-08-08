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
			// WS_EX_COMPOSITED hands double-buffering to DWM instead of this
			// app managing an off-screen GDI bitmap itself -- a prior
			// hand-rolled attempt (create/BitBlt/destroy a compatible bitmap
			// every WM_PAINT) reliably deadlocked under rapid repeated
			// WM_MOUSEWHEEL messages, and a second attempt using a cached,
			// reused back buffer (avoiding the per-frame alloc churn) still
			// produced a reproducible hang. This flag needs zero custom GDI
			// resource lifecycle in application code, so it can't reintroduce
			// that class of bug.
			ExStyle(co.WS_EX_COMPOSITED),
	)

	sw.wnd.On().WmCreate(func(p ui.WmCreate) int {
		sw.wnd.Hwnd().DwmSetWindowAttribute(win.DwmAttrUseImmersiveDarkMode(true))
		sw.clampToWorkArea()
		if big, small := loadAppIcons(); big != 0 || small != 0 {
			setWindowIcon(sw.wnd.Hwnd(), big, small)
		}
		return 0
	})

	// WM_MOUSEWHEEL (0x020A) has no typed windigo wrapper, so it's
	// registered via the generic Wm() escape hatch. Only reachable when the
	// window can't show all its content at once (see clampToWorkArea and
	// contentHeight above) -- on a tall enough screen maxScroll is 0 and
	// every wheel notch is a no-op.
	sw.wnd.On().Wm(co.WM(0x020A), func(p ui.Wm) uintptr {
		delta := int32(int16(uint16(uint32(p.WParam) >> 16)))
		clientRc, _ := sw.wnd.Hwnd().GetClientRect()
		maxScroll := sw.contentHeight - (clientRc.Bottom - clientRc.Top)
		if maxScroll < 0 {
			maxScroll = 0
		}
		step := dpiXOnly(60)
		sw.scrollY -= (delta / 120) * int32(step)
		if sw.scrollY < 0 {
			sw.scrollY = 0
		}
		if sw.scrollY > maxScroll {
			sw.scrollY = maxScroll
		}
		sw.wnd.Hwnd().InvalidateRect(nil, false)
		return 0
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
		hdc.FillRect(&clientRc, sw.res.brushBg)

		// Shift the DC's logical origin down by the scroll offset so every
		// existing drawXxx call (all written in fixed content-space
		// coordinates) renders shifted without needing to thread scrollY
		// through each one individually. windigo doesn't wrap
		// SetWindowOrgEx, hence the raw syscall above.
		setWindowOrgEx(hdc, 0, sw.scrollY)
		sw.buttons = sw.paint(hdc)
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
		sw.res.release()
	})

	return sw
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
