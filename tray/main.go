//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Win32 constants ───────────────────────────────────────────────────────────

const (
	WM_APP          = 0x8000
	WM_APP_REFRESH  = WM_APP + 1 // posted by poll goroutine to msgWnd
	WM_TRAYNOTIFY   = WM_APP + 2 // Shell_NotifyIcon callback message
	WM_DESTROY      = 0x0002
	WM_COMMAND      = 0x0111
	WM_CLOSE        = 0x0010
	WM_LBUTTONDBLCLK = 0x0203
	WM_RBUTTONUP    = 0x0205
	WM_LBUTTONUP    = 0x0202

	NIM_ADD    = 0
	NIM_MODIFY = 1
	NIM_DELETE = 2
	NIF_MESSAGE = 0x0001
	NIF_ICON    = 0x0002
	NIF_TIP     = 0x0004

	IDI_HAND        = 32513
	IDI_EXCLAMATION = 32515
	IDI_ASTERISK    = 32516
	IDI_SHIELD      = 32518
	IMAGE_ICON      = 1
	LR_SHARED       = 0x8000

	MF_STRING    = 0x0000
	MF_SEPARATOR = 0x0800
	MF_GRAYED    = 0x0001
	TPM_RETURNCMD   = 0x0100
	TPM_BOTTOMALIGN = 0x0020
	TPM_RIGHTALIGN  = 0x0008
	TPM_NONOTIFY    = 0x0080

	IDM_OPEN      = 0x1001
	IDM_EXPORT    = 0x1002
	IDM_DASHBOARD = 0x1003
	IDM_EXIT      = 0x1004

	WS_OVERLAPPED  = 0x00000000
	WS_CAPTION     = 0x00C00000
	WS_SYSMENU     = 0x00080000
	WS_MINIMIZEBOX = 0x00020000
	SW_SHOW        = 5
	SW_HIDE        = 0
	SW_RESTORE     = 9

	CS_HREDRAW = 0x0002
	CS_VREDRAW = 0x0001
)

// ── Win32 structs ─────────────────────────────────────────────────────────────

// notifyIconData mirrors NOTIFYICONDATAW on x64.
// Layout verified against Windows SDK: sizeof = 976.
type notifyIconData struct {
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

type winMsg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

type wndClassEx struct {
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

type point struct{ X, Y int32 }

// ── Win32 lazy procs ──────────────────────────────────────────────────────────

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procSetWindowPos        = user32.NewProc("SetWindowPos")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procLoadImageW          = user32.NewProc("LoadImageW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procRegisterWindowMessage = user32.NewProc("RegisterWindowMessageW")
	procPostMessage         = user32.NewProc("PostMessageW")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")
	procShellNotifyIconW    = shell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW       = shell32.NewProc("ShellExecuteW")
)

// ── Globals ───────────────────────────────────────────────────────────────────

var (
	hInst      uintptr
	msgWnd     uintptr // hidden message-only window
	taskbarMsg uint32  // WM_TASKBARCREATED

	// status window — created once, show/hide on demand
	statusWndHandle uintptr

	// current data (updated by poll goroutine, read by main thread)
	dataMu  sync.RWMutex
	curData *AllData

	apiCli *APIClient

	trayIconGreen  uintptr
	trayIconAmber  uintptr
	trayIconRed    uintptr

	msgWndCB = windows.NewCallback(msgWndProc)
)

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	runtime.LockOSThread()
	dbg("main() started")

	hInst, _, _ = procGetModuleHandleW.Call(0)

	// Try to connect to the agent API; non-fatal if not yet available.
	if cli, err := newAPIClient(); err == nil {
		apiCli = cli
		dbg("api client ready")
	} else {
		dbg("api client unavailable: " + err.Error())
		log.Printf("[!] agent API: %v — will retry", err)
	}

	// Register WM_TASKBARCREATED so we can re-add the tray icon if Explorer restarts.
	taskbarCreated := windows.StringToUTF16Ptr("TaskbarCreated")
	taskbarMsg32, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(taskbarCreated)))
	taskbarMsg = uint32(taskbarMsg32)

	// Create a hidden window to receive tray callbacks. We use a normal
	// (never-shown) top-level window rather than a message-only window
	// (HWND_MESSAGE) because HWND_MESSAGE creation fails on some systems
	// and a hidden normal window receives WM_TRAYNOTIFY just as reliably.
	clsName := windows.StringToUTF16Ptr("BASAgentTrayMsgWnd")
	wc := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   msgWndCB,
		Instance:  hInst,
		ClassName: clsName,
	}
	atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	dbg(fmt.Sprintf("RegisterClassEx(msg) atom=%d err=%v", atom, regErr))
	title := windows.StringToUTF16Ptr("BAS Agent Tray")
	msgWnd, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsName)),
		uintptr(unsafe.Pointer(title)),
		WS_OVERLAPPED, // not WS_VISIBLE — window is never shown
		0, 0, 0, 0,
		0, // parent = desktop (not HWND_MESSAGE)
		0, hInst, 0,
	)
	if msgWnd == 0 {
		le := windows.GetLastError()
		dbg(fmt.Sprintf("CreateWindowEx(msg) FAILED lastErr=%v", le))
	}
	dbg(fmt.Sprintf("msgWnd=%d", msgWnd))

	// Load status window tray icons from system stock.
	trayIconGreen, _, _ = procLoadImageW.Call(0, IDI_SHIELD, IMAGE_ICON, 0, 0, LR_SHARED)
	trayIconAmber, _, _ = procLoadImageW.Call(0, IDI_ASTERISK, IMAGE_ICON, 0, 0, LR_SHARED)
	trayIconRed, _, _ = procLoadImageW.Call(0, IDI_HAND, IMAGE_ICON, 0, 0, LR_SHARED)

	addTrayIcon(trayIconGreen, "BAS Agent - Connecting...")
	dbg("tray icon added")
	createStatusWindow()
	dbg(fmt.Sprintf("status window created=%d", statusWndHandle))

	// Initial fetch.
	go func() {
		if apiCli != nil {
			d := apiCli.fetchAll()
			dataMu.Lock()
			curData = d
			dataMu.Unlock()
			procPostMessage.Call(msgWnd, WM_APP_REFRESH, 0, 0)
		}
	}()

	// Poll every 5 seconds.
	go func() {
		t := time.NewTicker(5 * time.Second)
		for range t.C {
			if apiCli == nil {
				if cli, err := newAPIClient(); err == nil {
					apiCli = cli
				}
			}
			if apiCli != nil {
				d := apiCli.fetchAll()
				dataMu.Lock()
				curData = d
				dataMu.Unlock()
				procPostMessage.Call(msgWnd, WM_APP_REFRESH, 0, 0)
			}
		}
	}()

	// Message loop.
	dbg("entering message loop")
	var msg winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 || r == ^uintptr(0) {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	dbg("message loop exited")

	removeTrayIcon()
}

// ── Tray icon management ──────────────────────────────────────────────────────

func addTrayIcon(icon uintptr, tip string) {
	nid := notifyIconData{}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = msgWnd
	nid.UID = 1
	nid.UFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE
	nid.UCallbackMessage = WM_TRAYNOTIFY
	nid.HIcon = icon
	copyTip(&nid.SzTip, tip)
	procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
}

func updateTrayIcon(icon uintptr, tip string) {
	nid := notifyIconData{}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = msgWnd
	nid.UID = 1
	nid.UFlags = NIF_ICON | NIF_TIP
	nid.HIcon = icon
	copyTip(&nid.SzTip, tip)
	procShellNotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
}

func removeTrayIcon() {
	nid := notifyIconData{}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = msgWnd
	nid.UID = 1
	procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
}

func copyTip(dst *[128]uint16, s string) {
	p, _ := windows.UTF16FromString(s)
	for i, c := range p {
		if i >= 127 {
			break
		}
		dst[i] = c
	}
}

// ── Message window procedure ──────────────────────────────────────────────────

func msgWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	defer func() {
		if r := recover(); r != nil {
			dbg(fmt.Sprintf("PANIC in msgWndProc msg=0x%X: %v", msg, r))
		}
	}()

	switch uint32(msg) {

	case WM_TRAYNOTIFY:
		event := uint32(lParam)
		switch event {
		case WM_LBUTTONDBLCLK, WM_LBUTTONUP:
			toggleStatusWindow()
		case WM_RBUTTONUP:
			showContextMenu()
		}
		return 0

	case WM_APP_REFRESH:
		dataMu.RLock()
		d := curData
		dataMu.RUnlock()
		refreshTrayAndWindow(d)
		return 0

	case WM_COMMAND:
		switch wParam & 0xFFFF {
		case IDM_OPEN:
			toggleStatusWindow()
		case IDM_EXPORT:
			doExport()
		case IDM_DASHBOARD:
			openDashboard()
		case IDM_EXIT:
			removeTrayIcon()
			procDestroyWindow.Call(statusWndHandle)
			procPostQuitMessage.Call(0)
		}
		return 0
	}

	if uint32(msg) == taskbarMsg {
		// Explorer restarted — re-add tray icon.
		dataMu.RLock()
		d := curData
		dataMu.RUnlock()
		icon := trayIcon(d)
		tip := trayTip(d)
		addTrayIcon(icon, tip)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func trayIcon(d *AllData) uintptr {
	if d == nil || d.Err != nil || d.Status == nil {
		return trayIconRed
	}
	if !d.Status.ServerConnected {
		return trayIconRed
	}
	if d.Status.Status != "idle" {
		return trayIconAmber
	}
	return trayIconGreen
}

func trayTip(d *AllData) string {
	if d == nil || d.Err != nil || d.Status == nil {
		return "BAS Agent - Service Offline"
	}
	label := "Protected"
	if !d.Status.ServerConnected {
		label = "Disconnected"
	} else if d.Status.Status != "idle" {
		label = "Simulation Running"
	}
	return fmt.Sprintf("BAS Agent - %s | %s", label, d.Status.Hostname)
}

func refreshTrayAndWindow(d *AllData) {
	updateTrayIcon(trayIcon(d), trayTip(d))
	if d != nil {
		updateWindowData(d)
	}
}

// ── Context menu ──────────────────────────────────────────────────────────────

func showContextMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	addMenuString(menu, IDM_OPEN, "Open Status Window")
	addMenuSep(menu)
	addMenuString(menu, IDM_EXPORT, "Export Diagnostic Bundle")
	addMenuString(menu, IDM_DASHBOARD, "Open BAS Dashboard")
	addMenuSep(menu)
	addMenuString(menu, IDM_EXIT, "Exit")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(msgWnd)
	cmd, _, _ := procTrackPopupMenu.Call(
		menu,
		TPM_RETURNCMD|TPM_BOTTOMALIGN|TPM_RIGHTALIGN|TPM_NONOTIFY,
		uintptr(pt.X), uintptr(pt.Y), 0, msgWnd, 0,
	)
	if cmd != 0 {
		procPostMessage.Call(msgWnd, WM_COMMAND, cmd, 0)
	}
}

func addMenuString(menu, id uintptr, label string) {
	p, _ := windows.UTF16PtrFromString(label)
	procAppendMenuW.Call(menu, MF_STRING, id, uintptr(unsafe.Pointer(p)))
}

func addMenuSep(menu uintptr) {
	procAppendMenuW.Call(menu, MF_SEPARATOR, 0, 0)
}

// ── Window visibility ─────────────────────────────────────────────────────────

func toggleStatusWindow() {
	if statusWndHandle == 0 {
		return
	}
	// Check if window is visible.
	// ShowWindow returns non-zero if window was previously visible.
	r, _, _ := procShowWindow.Call(statusWndHandle, SW_SHOW)
	if r != 0 {
		// Was visible — bring to front.
		procSetForegroundWindow.Call(statusWndHandle)
	} else {
		// Was hidden — center and show.
		centerWindow(statusWndHandle)
		procSetForegroundWindow.Call(statusWndHandle)
	}
}

func centerWindow(hwnd uintptr) {
	sw, _, _ := procGetSystemMetrics.Call(0 /*SM_CXSCREEN*/)
	sh, _, _ := procGetSystemMetrics.Call(1 /*SM_CYSCREEN*/)
	procSetWindowPos.Call(hwnd, 0,
		uintptr(int((int(sw)-statusWinW)/2)),
		uintptr(int((int(sh)-statusWinH)/2)),
		statusWinW, statusWinH, 0x0040 /*SWP_SHOWWINDOW*/)
}

// ── Actions ───────────────────────────────────────────────────────────────────

func doExport() {
	dataMu.RLock()
	d := curData
	dataMu.RUnlock()

	path, err := exportBundle(d)
	if err != nil {
		log.Printf("[!] export bundle: %v", err)
		return
	}
	log.Printf("[+] diagnostic bundle: %s", path)
	// Open the folder containing the bundle.
	dir, _ := windows.UTF16PtrFromString(fmt.Sprintf("/select,%s", path))
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString("explorer.exe")
	procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(target)),
		uintptr(unsafe.Pointer(dir)),
		0, SW_SHOW)
}

func openDashboard() {
	dataMu.RLock()
	d := curData
	dataMu.RUnlock()
	url := "http://localhost:9000"
	if d != nil && d.Status != nil && d.Status.ServerURL != "" {
		url = d.Status.ServerURL
	}
	p, _ := windows.UTF16PtrFromString(url)
	verb, _ := windows.UTF16PtrFromString("open")
	procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(p)),
		0, 0, SW_SHOW)
}

// Single-instance guard — exit if another tray instance is already running in
// this session. Uses a session-local mutex (no "Global\\" prefix) so it works
// when the tray runs unprivileged at login; "Global\\" would need a privilege
// the unprivileged tray does not have, which previously killed it on startup.
//
// CreateMutex succeeds even when the mutex already exists (returns a valid
// handle with last-error ERROR_ALREADY_EXISTS), so we must check the handle is
// valid AND whether it pre-existed — but the x/sys wrapper only returns an
// error on a zero handle. To detect a pre-existing instance reliably we open
// first, then create.
func checkSingleInstance() {
	name, _ := windows.UTF16PtrFromString("BASAgentTray_singleton")
	// Try to open an existing mutex first.
	if h, err := windows.OpenMutex(0x00100000 /*SYNCHRONIZE*/, false, name); err == nil && h != 0 {
		windows.CloseHandle(h)
		fmt.Fprintln(os.Stderr, "BAS Agent tray is already running.")
		os.Exit(0)
	}
	// Create and hold the mutex for the process lifetime.
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil && h == 0 {
		// Could not create the guard — continue anyway rather than failing to start.
		dbg("single-instance: create mutex failed: " + err.Error())
		return
	}
	_ = h // leaked intentionally to hold the mutex for process lifetime
}

// ── Debug logging ─────────────────────────────────────────────────────────────
// Writes to %ProgramData%\BASAgent\tray-debug.txt (fallback %TEMP%). Used to
// diagnose silent exits. Remove or gate behind a flag once the tray is stable.

var dbgPath string

func dbg(msg string) {
	if dbgPath == "" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = os.Getenv("TEMP")
		}
		dbgPath = base + `\BASAgent\tray-debug.txt`
	}
	f, err := os.OpenFile(dbgPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// fall back to TEMP if ProgramData\BASAgent isn't writable
		dbgPath = os.Getenv("TEMP") + `\bas-tray-debug.txt`
		f, err = os.OpenFile(dbgPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
	}
	fmt.Fprintf(f, "%s  %s\n", time.Now().Format("15:04:05.000"), msg)
	f.Close()
}

func init() {
	dbg("=== tray launch ===")
	checkSingleInstance()
}
