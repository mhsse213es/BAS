//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Lazy DLLs / procs (uniquely named to avoid clashing with other agent
//    Win32 declarations in elevate.go / dismiss_windows.go / etc.) ────────────

var (
	trayUser32   = windows.NewLazySystemDLL("user32.dll")
	trayShell32  = windows.NewLazySystemDLL("shell32.dll")
	trayKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	trayRegisterClassEx  = trayUser32.NewProc("RegisterClassExW")
	trayCreateWindowEx   = trayUser32.NewProc("CreateWindowExW")
	trayDefWindowProc    = trayUser32.NewProc("DefWindowProcW")
	trayGetMessage       = trayUser32.NewProc("GetMessageW")
	trayTranslateMessage = trayUser32.NewProc("TranslateMessage")
	trayDispatchMessage  = trayUser32.NewProc("DispatchMessageW")
	trayPostQuitMessage  = trayUser32.NewProc("PostQuitMessage")
	traySetForeground    = trayUser32.NewProc("SetForegroundWindow")
	trayLoadImage        = trayUser32.NewProc("LoadImageW")
	trayCreatePopupMenu  = trayUser32.NewProc("CreatePopupMenu")
	trayAppendMenu       = trayUser32.NewProc("AppendMenuW")
	trayTrackPopupMenu   = trayUser32.NewProc("TrackPopupMenu")
	trayDestroyMenu      = trayUser32.NewProc("DestroyMenu")
	trayGetCursorPos     = trayUser32.NewProc("GetCursorPos")
	trayRegisterWinMsg   = trayUser32.NewProc("RegisterWindowMessageW")
	trayPostMessage      = trayUser32.NewProc("PostMessageW")
	trayGetModuleHandle  = trayKernel32.NewProc("GetModuleHandleW")
	trayShellNotifyIcon  = trayShell32.NewProc("Shell_NotifyIconW")
)

// ── Constants ────────────────────────────────────────────────────────────────

const (
	tWM_APP          = 0x8000
	tWM_TRAYNOTIFY   = tWM_APP + 2
	tWM_COMMAND      = 0x0111
	tWM_LBUTTONUP    = 0x0202
	tWM_LBUTTONDBLCLK = 0x0203
	tWM_RBUTTONUP    = 0x0205

	tNIM_ADD    = 0
	tNIM_DELETE = 2
	tNIF_MESSAGE = 0x0001
	tNIF_ICON    = 0x0002
	tNIF_TIP     = 0x0004

	tIDI_SHIELD = 32518
	tIMAGE_ICON = 1
	tLR_SHARED  = 0x8000
	tIDC_ARROW  = 32512

	tMF_STRING    = 0x0000
	tMF_SEPARATOR = 0x0800
	tTPM_RETURNCMD = 0x0100
	tTPM_RIGHTALIGN = 0x0008
	tTPM_BOTTOMALIGN = 0x0020
	tTPM_NONOTIFY = 0x0080

	tWS_OVERLAPPED = 0x00000000

	tIDM_OPEN    = 0x2001
	tIDM_EXPORT  = 0x2002
	tIDM_LOGS    = 0x2003
	tIDM_EXIT    = 0x2009
)

// ── Structs ──────────────────────────────────────────────────────────────────

type trayNotifyIconData struct {
	CbSize           uint32
	_pad0            [4]byte
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	_pad1            [4]byte
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

type trayWndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type trayWinMsg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

type trayPoint struct{ X, Y int32 }

// ── State ────────────────────────────────────────────────────────────────────

var (
	trayHInst  uintptr
	trayWnd    uintptr
	trayIcon   uintptr
	trayTaskbarMsg uint32
	trayProcCB = windows.NewCallback(trayWndProc)

	// persistent UTF16 pointers (avoid GC of buffers Win32 still references)
	trayClsName  = windows.StringToUTF16Ptr("BASAgentTrayWnd")
	trayWndTitle = windows.StringToUTF16Ptr("BAS Agent")
)

// runTray shows the persistent system-tray icon. Left-click / double-click opens
// the WebView2 status console (spawned as a separate --status-window process).
func runTray() {
	runtime.LockOSThread()

	if trayAlreadyRunning() {
		return
	}

	trayHInst, _, _ = trayGetModuleHandle.Call(0)

	tc, _, _ := trayRegisterWinMsg.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("TaskbarCreated"))))
	trayTaskbarMsg = uint32(tc)

	cur, _, _ := trayLoadImage.Call(0, tIDC_ARROW, tIMAGE_ICON, 0, 0, tLR_SHARED)
	wc := trayWndClassEx{
		Size:      uint32(unsafe.Sizeof(trayWndClassEx{})),
		WndProc:   trayProcCB,
		Instance:  trayHInst,
		Cursor:    cur,
		ClassName: trayClsName,
	}
	trayRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	// Hidden normal window (NOT HWND_MESSAGE — that fails on some systems).
	trayWnd, _, _ = trayCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(trayClsName)),
		uintptr(unsafe.Pointer(trayWndTitle)),
		tWS_OVERLAPPED,
		0, 0, 0, 0,
		0, 0, trayHInst, 0,
	)

	trayIcon, _, _ = trayLoadImage.Call(0, tIDI_SHIELD, tIMAGE_ICON, 0, 0, tLR_SHARED)
	trayAddIcon("Audspect BAS Agent")

	var msg trayWinMsg
	for {
		r, _, _ := trayGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 || r == ^uintptr(0) {
			break
		}
		trayTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		trayDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	trayRemoveIcon()
}

func trayAddIcon(tip string) {
	nid := trayNotifyIconData{}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = trayWnd
	nid.UID = 1
	nid.UFlags = tNIF_ICON | tNIF_TIP | tNIF_MESSAGE
	nid.UCallbackMessage = tWM_TRAYNOTIFY
	nid.HIcon = trayIcon
	trayCopyTip(&nid.SzTip, tip)
	trayShellNotifyIcon.Call(tNIM_ADD, uintptr(unsafe.Pointer(&nid)))
}

func trayRemoveIcon() {
	nid := trayNotifyIconData{}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = trayWnd
	nid.UID = 1
	trayShellNotifyIcon.Call(tNIM_DELETE, uintptr(unsafe.Pointer(&nid)))
}

func trayCopyTip(dst *[128]uint16, s string) {
	p, _ := windows.UTF16FromString(s)
	for i, c := range p {
		if i >= 127 {
			break
		}
		dst[i] = c
	}
}

func trayWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	defer func() {
		if r := recover(); r != nil {
			// never let a callback panic kill the tray
			_ = r
		}
	}()

	switch uint32(msg) {
	case tWM_TRAYNOTIFY:
		switch uint32(lParam) {
		case tWM_LBUTTONUP, tWM_LBUTTONDBLCLK:
			openStatusWindow()
		case tWM_RBUTTONUP:
			trayShowMenu()
		}
		return 0

	case tWM_COMMAND:
		switch wParam & 0xFFFF {
		case tIDM_OPEN:
			openStatusWindow()
		case tIDM_EXPORT:
			if path, err := exportDiagnosticBundle(); err == nil {
				revealInExplorer(path)
			}
		case tIDM_LOGS:
			revealInExplorer(logDir())
		case tIDM_EXIT:
			trayRemoveIcon()
			trayPostQuitMessage.Call(0)
		}
		return 0
	}

	if uint32(msg) == trayTaskbarMsg {
		trayAddIcon("Audspect BAS Agent") // Explorer restarted
		return 0
	}

	r, _, _ := trayDefWindowProc.Call(hwnd, msg, wParam, lParam)
	return r
}

func trayShowMenu() {
	menu, _, _ := trayCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer trayDestroyMenu.Call(menu)

	trayMenuItem(menu, tIDM_OPEN, "Open Status Console")
	trayMenuSep(menu)
	trayMenuItem(menu, tIDM_EXPORT, "Export Diagnostic Bundle")
	trayMenuItem(menu, tIDM_LOGS, "Open Logs Folder")
	trayMenuSep(menu)
	trayMenuItem(menu, tIDM_EXIT, "Exit")

	var pt trayPoint
	trayGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	traySetForeground.Call(trayWnd)
	cmd, _, _ := trayTrackPopupMenu.Call(menu,
		tTPM_RETURNCMD|tTPM_RIGHTALIGN|tTPM_BOTTOMALIGN|tTPM_NONOTIFY,
		uintptr(pt.X), uintptr(pt.Y), 0, trayWnd, 0)
	if cmd != 0 {
		trayPostMessage.Call(trayWnd, tWM_COMMAND, cmd, 0)
	}
}

func trayMenuItem(menu, id uintptr, label string) {
	p, _ := windows.UTF16PtrFromString(label)
	trayAppendMenu.Call(menu, tMF_STRING, id, uintptr(unsafe.Pointer(p)))
}
func trayMenuSep(menu uintptr) { trayAppendMenu.Call(menu, tMF_SEPARATOR, 0, 0) }

// openStatusWindow spawns the WebView2 console as a separate process so it has
// its own message loop independent of the tray.
//
// The console is a singleton: if one is already open, surface it instead of
// spawning another bas_agent.exe --status-window. The spawned process also
// self-guards (statusWindowGuard), so this focus-before-spawn check is
// belt-and-suspenders that additionally avoids creating a short-lived duplicate
// process on every tray click.
func openStatusWindow() {
	if focusStatusWindow() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "--status-window")
	if err := cmd.Start(); err != nil {
		log.Printf("[tray] open status console: %v", err)
	}
}

// trayAlreadyRunning returns true if another tray instance holds the singleton
// mutex in this session. Session-local (no Global\) so it works unprivileged.
func trayAlreadyRunning() bool {
	name, _ := windows.UTF16PtrFromString("BASAgentTray_singleton")
	if h, err := windows.OpenMutex(0x00100000 /*SYNCHRONIZE*/, false, name); err == nil && h != 0 {
		windows.CloseHandle(h)
		return true
	}
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil && h == 0 {
		return false // couldn't create guard; run anyway
	}
	_ = h // held for process lifetime
	return false
}

var _ = fmt.Sprintf // keep fmt imported for future use
