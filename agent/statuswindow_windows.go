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
}

func newWindigoWindow() *windigoWindow {
	sw := &windigoWindow{res: newResources()}

	cx, cy := ui.Dpi(920, 1320)
	sw.wnd = ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent").
			Size(cx, cy).
			ClassBrush(sw.res.brushBg).
			ClassStyle(co.CS_HREDRAW | co.CS_VREDRAW),
	)

	sw.wnd.On().WmCreate(func(p ui.WmCreate) int {
		sw.wnd.Hwnd().DwmSetWindowAttribute(win.DwmAttrUseImmersiveDarkMode(true))
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
	return nil
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
