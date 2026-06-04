//go:build windows

//go:generate rsrc -manifest installer.exe.manifest -arch amd64 -o rsrc.syso

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Win32 lazy DLL procs ──────────────────────────────────────────────────────

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procLoadCursor       = user32.NewProc("LoadCursorW")
	procGetWindowText    = user32.NewProc("GetWindowTextW")
	procSetWindowText    = user32.NewProc("SetWindowTextW")
	procSendMessage      = user32.NewProc("SendMessageW")
	procMessageBox       = user32.NewProc("MessageBoxW")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	procGetClientRect    = user32.NewProc("GetClientRect")
	procBeginPaint       = user32.NewProc("BeginPaint")
	procEndPaint         = user32.NewProc("EndPaint")
	procFillRect         = user32.NewProc("FillRect")
	procSetBkMode        = user32.NewProc("SetBkMode")
	procSetTextColor     = user32.NewProc("SetTextColor")
	procDrawText         = user32.NewProc("DrawTextW")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procInvalidateRect   = user32.NewProc("InvalidateRect")

	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procCreateFont       = gdi32.NewProc("CreateFontW")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procGetStockObject   = gdi32.NewProc("GetStockObject")

	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
)

// ── Win32 constants ───────────────────────────────────────────────────────────

const (
	WM_CREATE         = 0x0001
	WM_DESTROY        = 0x0002
	WM_PAINT          = 0x000F
	WM_COMMAND        = 0x0111
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLOREDIT   = 0x0133
	WM_SETFONT        = 0x0030

	WS_OVERLAPPED   = 0x00000000
	WS_CAPTION      = 0x00C00000
	WS_SYSMENU      = 0x00080000
	WS_MINIMIZEBOX  = 0x00020000
	WS_VISIBLE      = 0x10000000
	WS_CHILD        = 0x40000000
	WS_BORDER       = 0x00800000
	WS_TABSTOP      = 0x00010000
	WS_VSCROLL      = 0x00200000
	ES_LEFT         = 0x0000
	ES_MULTILINE    = 0x0004
	ES_AUTOVSCROLL  = 0x0040
	ES_PASSWORD     = 0x0020
	ES_READONLY     = 0x0800
	SS_LEFT         = 0x00000000
	BS_PUSHBUTTON   = 0x00000000
	BS_DEFPUSHBUTTON = 0x00000001

	SW_SHOW    = 5
	TRANSPARENT = 1
	WHITE_BRUSH = 0

	SM_CXSCREEN = 0
	SM_CYSCREEN = 1

	DT_LEFT     = 0x00000000
	DT_CENTER   = 0x00000001
	DT_VCENTER  = 0x00000004
	DT_SINGLELINE = 0x00000020

	IDC_URL     = 101
	IDC_SECRET  = 102
	IDC_ENV     = 103
	IDC_INSTALL = 104
	IDC_CANCEL  = 105
	IDC_STATUS  = 106

	WINW = 520
	WINH = 430
	HDR  = 88 // header height

	// Colours (BGR for Win32)
	colHdrBg   = 0x201408 // #0b1420 dark navy
	colHdrText = 0xFFFFFF
	colBodyBg  = 0xF5F5F5
	colAccent  = 0xF78102 // #2f81f7 blue
	colLabel   = 0x333333
)

// ── Win32 structs ─────────────────────────────────────────────────────────────

type WNDCLASSEX struct {
	Size        uint32
	Style       uint32
	WndProc     uintptr
	ClsExtra    int32
	WndExtra    int32
	Instance    uintptr
	Icon        uintptr
	Cursor      uintptr
	Background  uintptr
	MenuName    *uint16
	ClassName   *uint16
	IconSm      uintptr
}

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type PAINTSTRUCT struct {
	Hdc         uintptr
	Erase       int32
	RcPaint     [4]int32 // left,top,right,bottom
	Restore     int32
	IncUpdate   int32
	Reserved    [32]byte
}

// ── Global state ──────────────────────────────────────────────────────────────

var (
	hInst      uintptr
	hMainWnd   uintptr
	hURLEdit   uintptr
	hSecEdit   uintptr
	hEnvEdit   uintptr
	hInstBtn   uintptr
	hCancelBtn uintptr
	hStatus    uintptr
	hdrBrush   uintptr
	bodyBrush  uintptr
	hFont      uintptr
	hFontBold  uintptr

	wndProcCB = syscall.NewCallback(wndProc)

	installing bool
)

// ── Win32 helpers ─────────────────────────────────────────────────────────────

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func createWindow(exStyle uint32, class, title string, style uint32,
	x, y, w, h int, parent, menu, inst uintptr) uintptr {
	hwnd, _, _ := procCreateWindowEx.Call(
		uintptr(exStyle), uintptr(unsafe.Pointer(utf16(class))),
		uintptr(unsafe.Pointer(utf16(title))),
		uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, menu, inst, 0,
	)
	return hwnd
}

func getWindowText(hwnd uintptr) string {
	buf := make([]uint16, 512)
	procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 512)
	return windows.UTF16ToString(buf)
}

func setWindowText(hwnd uintptr, s string) {
	procSetWindowText.Call(hwnd, uintptr(unsafe.Pointer(utf16(s))))
}

func appendStatus(s string) {
	cur := getWindowText(hStatus)
	if cur != "" {
		cur += "\r\n"
	}
	setWindowText(hStatus, cur+s)
	// Scroll to bottom
	procSendMessage.Call(hStatus, 0x115 /*WM_VSCROLL*/, 7 /*SB_BOTTOM*/, 0)
}

func sendFont(hwnd, font uintptr) {
	procSendMessage.Call(hwnd, WM_SETFONT, font, 1)
}

// ── Window procedure ──────────────────────────────────────────────────────────

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {

	case WM_CREATE:
		hdrBrush, _, _ = procCreateSolidBrush.Call(colHdrBg)
		bodyBrush, _, _ = procCreateSolidBrush.Call(colBodyBg)
		hFont, _, _ = procCreateFont.Call(
			16, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(utf16("Segoe UI"))),
		)
		hFontBold, _, _ = procCreateFont.Call(
			16, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(utf16("Segoe UI"))),
		)
		createControls(hwnd)
		return 0

	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))

		// Header background
		var hdrRect [4]int32
		hdrRect[2] = WINW
		hdrRect[3] = HDR
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&hdrRect)), hdrBrush)

		// Header title
		procSetBkMode.Call(hdc, TRANSPARENT)
		procSetTextColor.Call(hdc, colHdrText)
		titleFont, _, _ := procCreateFont.Call(
			22, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(utf16("Segoe UI"))),
		)
		procSelectObject.Call(hdc, titleFont)
		var tr [4]int32
		tr[0], tr[1], tr[2], tr[3] = 20, 16, WINW-20, 48
		procDrawText.Call(hdc, uintptr(unsafe.Pointer(utf16("BAS Platform Agent Setup"))),
			^uintptr(0), uintptr(unsafe.Pointer(&tr)),
			DT_LEFT|DT_VCENTER|DT_SINGLELINE)

		// Subtitle
		subFont, _, _ := procCreateFont.Call(
			14, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(utf16("Segoe UI"))),
		)
		procSelectObject.Call(hdc, subFont)
		procSetTextColor.Call(hdc, 0xCCCCCC)
		var sr [4]int32
		sr[0], sr[1], sr[2], sr[3] = 20, 48, WINW-20, 76
		procDrawText.Call(hdc, uintptr(unsafe.Pointer(utf16("Breach & Attack Simulation Platform  ·  Audspect Security"))),
			^uintptr(0), uintptr(unsafe.Pointer(&sr)),
			DT_LEFT|DT_VCENTER|DT_SINGLELINE)

		// Body background
		var bodyRect [4]int32
		bodyRect[0], bodyRect[1], bodyRect[2], bodyRect[3] = 0, HDR, WINW, WINH
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&bodyRect)), bodyBrush)

		procDeleteObject.Call(titleFont)
		procDeleteObject.Call(subFont)
		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case WM_CTLCOLORSTATIC:
		procSetBkMode.Call(wParam, TRANSPARENT)
		procSetTextColor.Call(wParam, colLabel)
		return bodyBrush

	case WM_CTLCOLOREDIT:
		procSetBkMode.Call(wParam, 1 /*OPAQUE*/)
		procSetTextColor.Call(wParam, 0x111111)
		white, _, _ := procGetStockObject.Call(WHITE_BRUSH)
		return white

	case WM_COMMAND:
		id := wParam & 0xFFFF
		switch id {
		case IDC_INSTALL:
			if !installing {
				go runInstall(hwnd)
			}
		case IDC_CANCEL:
			procDestroyWindow.Call(hwnd)
		}
		return 0

	case WM_DESTROY:
		procDeleteObject.Call(hdrBrush)
		procDeleteObject.Call(bodyBrush)
		procDeleteObject.Call(hFont)
		procDeleteObject.Call(hFontBold)
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wParam, lParam)
	return r
}

func createControls(hwnd uintptr) {
	label := func(text string, x, y, w, h int) uintptr {
		hw := createWindow(0, "STATIC", text,
			WS_CHILD|WS_VISIBLE|SS_LEFT, x, y, w, h, hwnd, 0, hInst)
		sendFont(hw, hFont)
		return hw
	}
	edit := func(id, x, y, w, h int, style uint32) uintptr {
		hw := createWindow(0x200 /*WS_EX_CLIENTEDGE*/, "EDIT", "",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|style, x, y, w, h,
			hwnd, uintptr(id), hInst)
		sendFont(hw, hFont)
		return hw
	}

	const lx = 30 // left margin
	const fw = WINW - 60 // field width

	label("Server URL  (e.g. http://10.0.0.5:9000)", lx, HDR+16, fw, 20)
	hURLEdit = edit(IDC_URL, lx, HDR+38, fw, 26, ES_LEFT)
	setWindowText(hURLEdit, "http://")

	label("Agent Secret", lx, HDR+76, fw, 20)
	hSecEdit = edit(IDC_SECRET, lx, HDR+98, fw, 26, ES_PASSWORD)

	label("Environment Label", lx, HDR+136, fw, 20)
	hEnvEdit = edit(IDC_ENV, lx, HDR+158, fw, 26, ES_LEFT)
	setWindowText(hEnvEdit, "Production")

	label("Installation Log", lx, HDR+196, fw, 20)
	hStatus = createWindow(0x200, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		lx, HDR+218, fw, 118, hwnd, uintptr(IDC_STATUS), hInst)
	sendFont(hStatus, hFont)

	hInstBtn = createWindow(0, "BUTTON", "  Validate & Install  ",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,
		lx, HDR+350, 200, 34, hwnd, uintptr(IDC_INSTALL), hInst)
	sendFont(hInstBtn, hFontBold)

	hCancelBtn = createWindow(0, "BUTTON", "Exit",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		lx+210, HDR+350, 80, 34, hwnd, uintptr(IDC_CANCEL), hInst)
	sendFont(hCancelBtn, hFont)
}

// ── Install logic ─────────────────────────────────────────────────────────────

func runInstall(hwnd uintptr) {
	installing = true
	procEnableWindow.Call(hInstBtn, 0) // disable button

	serverURL := getWindowText(hURLEdit)
	secret := getWindowText(hSecEdit)
	envLabel := getWindowText(hEnvEdit)

	// Validate inputs
	if serverURL == "" || serverURL == "http://" {
		appendStatus("[ERROR] Server URL is required.")
		procEnableWindow.Call(hInstBtn, 1)
		installing = false
		return
	}
	if secret == "" {
		appendStatus("[ERROR] Agent Secret is required.")
		procEnableWindow.Call(hInstBtn, 1)
		installing = false
		return
	}

	// Step 1: Validate connectivity + secret
	appendStatus("[1/4] Validating server connectivity and secret...")
	if err := validateEnrollment(serverURL, secret); err != nil {
		appendStatus("[ERROR] " + err.Error())
		appendStatus("       Check the Server URL and Agent Secret, then try again.")
		procEnableWindow.Call(hInstBtn, 1)
		installing = false
		return
	}
	appendStatus("[1/4] Server validated OK.")

	// Step 2: Extract agent binary
	appendStatus("[2/4] Extracting agent binary...")
	installDir := filepath.Join(os.Getenv("ProgramFiles"), "BASAgent")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		appendStatus("[ERROR] Could not create install directory: " + err.Error())
		procEnableWindow.Call(hInstBtn, 1)
		installing = false
		return
	}
	agentPath := filepath.Join(installDir, "bas_agent.exe")
	if err := os.WriteFile(agentPath, agentData, 0755); err != nil {
		appendStatus("[ERROR] Could not write agent binary: " + err.Error())
		procEnableWindow.Call(hInstBtn, 1)
		installing = false
		return
	}
	appendStatus("[2/4] Agent extracted to: " + agentPath)

	// Step 3: Install service
	appendStatus("[3/4] Installing BASAgent service...")
	cmd := exec.Command(agentPath,
		"--install",
		"--server", serverURL,
		"--env", envLabel,
		"--secret", secret,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		appendStatus("[ERROR] Service install failed: " + err.Error())
		if len(out) > 0 {
			appendStatus("        " + string(out))
		}
		procEnableWindow.Call(hInstBtn, 1)
		installing = false
		return
	}
	if len(out) > 0 {
		for _, line := range splitLines(string(out)) {
			if line != "" {
				appendStatus("        " + line)
			}
		}
	}

	// Step 4: Start service
	appendStatus("[4/4] Starting BASAgent service...")
	sc := exec.Command("sc", "start", "BASAgent")
	sc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	scOut, scErr := sc.CombinedOutput()
	if scErr != nil {
		// Service may already be starting — check status
		appendStatus("[~] sc start: " + string(scOut))
	}

	appendStatus("")
	appendStatus("========================================")
	appendStatus("  BAS Agent installed and started.")
	appendStatus("  The agent will appear in the dashboard")
	appendStatus("  within 30 seconds.")
	appendStatus("========================================")

	setWindowText(hInstBtn, "  Installed  ")
	setWindowText(hCancelBtn, "Close")
	installing = false
}

// validateEnrollment calls POST /api/agents/enroll with a minimal payload to
// verify both the server URL and the agent secret before writing anything locally.
func validateEnrollment(serverURL, secret string) error {
	hostname, _ := os.Hostname()
	payload := map[string]string{
		"agentId":      "install-probe-" + hostname,
		"hostname":     hostname,
		"agentVersion": "installer",
	}
	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost,
		serverURL+"/api/agents/enroll", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", secret)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach server at %s — check URL and network", serverURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("agent secret rejected (HTTP 401) — check AGENT_SECRET on the server")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d — check server configuration", resp.StatusCode)
	}
	return nil
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
		} else if c != '\r' {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	// Win32 message loops must run on a single OS thread.
	runtime.LockOSThread()

	if !isElevated() {
		procMessageBox.Call(0,
			uintptr(unsafe.Pointer(utf16("This installer requires Administrator privileges.\n\nPlease right-click the file and choose \"Run as administrator\"."))),
			uintptr(unsafe.Pointer(utf16("BAS Agent Setup"))),
			0x10 /*MB_ICONERROR*/)
		return
	}

	hInst, _, _ = procGetModuleHandle.Call(0)

	className := utf16("BASInstallerWnd")
	wc := WNDCLASSEX{
		Size:       uint32(unsafe.Sizeof(WNDCLASSEX{})),
		WndProc:    wndProcCB,
		Instance:   hInst,
		Background: bodyBrush,
		ClassName:  className,
	}
	wc.Cursor, _, _ = procLoadCursor.Call(0, 32512 /*IDC_ARROW*/)
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	winStyle := uint32(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE)
	hMainWnd = createWindow(0, "BASInstallerWnd",
		"BAS Platform — Agent Setup",
		winStyle, 100, 100, WINW, WINH, 0, 0, hInst)

	if hMainWnd == 0 {
		procMessageBox.Call(0,
			uintptr(unsafe.Pointer(utf16("Failed to create installer window.\n\nThe installer may already be running, or Windows blocked the application."))),
			uintptr(unsafe.Pointer(utf16("BAS Agent Setup"))),
			0x10 /*MB_ICONERROR*/)
		return
	}

	// Center on screen
	sw, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	sh, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
	procSetWindowPos.Call(hMainWnd, 0,
		uintptr(int((int(sw)-WINW)/2)), uintptr(int((int(sh)-WINH)/2)), WINW, WINH,
		0x0040 /*SWP_SHOWWINDOW*/)

	procShowWindow.Call(hMainWnd, SW_SHOW)
	procUpdateWindow.Call(hMainWnd)

	var msg MSG
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 || r == ^uintptr(0) { // 0 = WM_QUIT, ^0 = error
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// ── UAC elevation ─────────────────────────────────────────────────────────────

var (
	shell32           = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute  = shell32.NewProc("ShellExecuteW")
)

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func selfElevate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exeW, _ := windows.UTF16PtrFromString(exe)
	verb, _ := windows.UTF16PtrFromString("runas")
	procShellExecute.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(exeW)),
		0, 0, SW_SHOW)
}
