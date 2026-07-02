//go:build windows

//go:generate rsrc -manifest installer.exe.manifest -arch amd64 -o rsrc.syso

package main

import (
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
	"golang.org/x/sys/windows/registry"
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
	procBeginPaint       = user32.NewProc("BeginPaint")
	procEndPaint         = user32.NewProc("EndPaint")
	procFillRect         = user32.NewProc("FillRect")
	procDrawText         = user32.NewProc("DrawTextW")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procInvalidateRect   = user32.NewProc("InvalidateRect")

	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procCreatePen        = gdi32.NewProc("CreatePen")
	procCreateFont       = gdi32.NewProc("CreateFontW")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procGetStockObject   = gdi32.NewProc("GetStockObject")
	procSetBkMode        = gdi32.NewProc("SetBkMode")
	procSetBkColor       = gdi32.NewProc("SetBkColor")
	procSetTextColor     = gdi32.NewProc("SetTextColor")
	procMoveToEx         = gdi32.NewProc("MoveToEx")
	procLineTo           = gdi32.NewProc("LineTo")
	procRoundRect        = gdi32.NewProc("RoundRect")

	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
)

// ── Win32 message / style constants ──────────────────────────────────────────

const (
	WM_CREATE         = 0x0001
	WM_DESTROY        = 0x0002
	WM_PAINT          = 0x000F
	WM_COMMAND        = 0x0111
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLOREDIT   = 0x0133
	WM_SETFONT        = 0x0030
	WM_DRAWITEM       = 0x002B

	WS_OVERLAPPED    = 0x00000000
	WS_CAPTION       = 0x00C00000
	WS_SYSMENU       = 0x00080000
	WS_MINIMIZEBOX   = 0x00020000
	WS_VISIBLE       = 0x10000000
	WS_CHILD         = 0x40000000
	WS_BORDER        = 0x00800000
	WS_TABSTOP       = 0x00010000
	WS_VSCROLL       = 0x00200000
	ES_LEFT          = 0x0000
	ES_MULTILINE     = 0x0004
	ES_AUTOVSCROLL   = 0x0040
	ES_PASSWORD      = 0x0020
	ES_READONLY      = 0x0800
	SS_LEFT          = 0x00000000
	BS_PUSHBUTTON    = 0x00000000
	BS_DEFPUSHBUTTON = 0x00000001
	BS_OWNERDRAW     = 0x0000000B // required for custom-painted buttons

	SW_SHOW    = 5
	TRANSPARENT = 1
	NULL_PEN    = 8

	SM_CXSCREEN = 0
	SM_CYSCREEN = 1

	DT_LEFT       = 0x00000000
	DT_CENTER     = 0x00000001
	DT_RIGHT      = 0x00000002
	DT_VCENTER    = 0x00000004
	DT_SINGLELINE = 0x00000020
	DT_NOCLIP     = 0x00000100

	ODS_SELECTED = 0x0001
)

// ── Control IDs ───────────────────────────────────────────────────────────────

const (
	IDC_URL     = 101
	IDC_SECRET  = 102
	IDC_ENV     = 103
	IDC_INSTALL = 104
	IDC_CANCEL  = 105
	IDC_STATUS  = 106
)

// ── Window geometry ───────────────────────────────────────────────────────────

const (
	WINW = 520
	WINH = 572
	HDR  = 108 // header stripe height (client coords)
	LPAD = 24  // left/right gutter
	FW   = WINW - LPAD*2 // usable field width = 472
	EDTH = 28  // edit control height
)

// Layout — all in client coordinates (y=0 at top of client area).
const (
	ySec1     = HDR + 14       // "CONFIGURATION" section label
	yURLLbl   = ySec1 + 20     // URL field label
	yURLEdit  = yURLLbl + 16   // URL edit, h=EDTH, ends 200
	ySecLbl   = yURLEdit + 36  // Secret field label
	ySecEdit  = ySecLbl + 16   // Secret edit, h=EDTH, ends 252
	yEnvLbl   = ySecEdit + 36  // Env label
	yEnvEdit  = yEnvLbl + 16   // Env edit, h=EDTH, ends 304
	yDivider  = yEnvEdit + 38  // horizontal rule
	ySec2     = yDivider + 10  // "INSTALLATION LOG" label
	yLog      = ySec2 + 20     // log edit area
	yBtns     = 498            // button row
	logH      = yBtns - yLog - 6
)

// ── Colours (Win32 COLORREF = 0x00BBGGRR) ────────────────────────────────────

const (
	colHdrBg     = uintptr(0x0020140B) // #0b1420 deep navy header
	colBodyBg    = uintptr(0x00382315) // #152338 dark navy body
	colSurface   = uintptr(0x00412A1B) // #1b2a41 input / elevated surface
	colLogBg     = uintptr(0x0020140B) // #0b1420 terminal log
	colAccent    = uintptr(0x00F7812F) // #2f81f7 accent blue
	colAccentPrs = uintptr(0x00D06A26) // darker blue for pressed state
	colBorder    = uintptr(0x004A3222) // #22324a border
	colTextPri   = uintptr(0x00F3EDE6) // #e6edf3 primary text
	colTextMut   = uintptr(0x00BCA99A) // #9aa9bc muted text
	colWhite     = uintptr(0x00FFFFFF)
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
	Hdc       uintptr
	Erase     int32
	RcPaint   [4]int32
	Restore   int32
	IncUpdate int32
	Reserved  [32]byte
}

// DRAWITEMSTRUCT — 64-bit layout has 4-byte pad after ItemState before HwndItem.
type DRAWITEMSTRUCT struct {
	CtlType    uint32
	CtlID      uint32
	ItemID     uint32
	ItemAction uint32
	ItemState  uint32
	_          uint32 // alignment
	HwndItem   uintptr
	HDC        uintptr
	RcItem     [4]int32 // left, top, right, bottom
	ItemData   uintptr
}

// ── Global handles ────────────────────────────────────────────────────────────

var (
	hInst      uintptr
	hMainWnd   uintptr
	hURLEdit   uintptr
	hSecEdit   uintptr
	hEnvEdit   uintptr
	hInstBtn   uintptr
	hCancelBtn uintptr
	hStatus    uintptr

	// GDI resources — created once in WM_CREATE, destroyed in WM_DESTROY.
	hdrBrush  uintptr
	bodyBrush uintptr
	surfBrush uintptr
	logBrush  uintptr

	hFont        uintptr // Segoe UI 15pt regular
	hFontBold    uintptr // Segoe UI 15pt bold
	hFontSmall   uintptr // Segoe UI 12pt regular (field labels)
	hFontSection uintptr // Segoe UI 11pt bold (section caps)
	hFontTitle   uintptr // Segoe UI 20pt bold (header title)
	hFontSub     uintptr // Segoe UI 13pt regular (header subtitle)
	hFontBadge   uintptr // Segoe UI 11pt bold (header badge)
	hFontMono    uintptr // Consolas 13pt (log area)

	wndProcCB = syscall.NewCallback(wndProc)
	installing bool
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func mkFont(size, weight int32, face string) uintptr {
	p := utf16(face)
	f, _, _ := procCreateFont.Call(
		uintptr(size), 0, 0, 0, uintptr(weight),
		0, 0, 0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(p)),
	)
	runtime.KeepAlive(p)
	return f
}

func createCtl(exStyle uint32, class, title string, style uint32,
	x, y, w, h int, parent, id, inst uintptr) uintptr {
	hwnd, _, _ := procCreateWindowEx.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(utf16(class))),
		uintptr(unsafe.Pointer(utf16(title))),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, id, inst, 0,
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
	procSendMessage.Call(hStatus, 0x115 /*WM_VSCROLL*/, 7 /*SB_BOTTOM*/, 0)
}

func setFont(hwnd, font uintptr) {
	procSendMessage.Call(hwnd, WM_SETFONT, font, 1)
}

// drawText draws s into the rectangle (x1,y1)-(x2,y2) with the given flags.
func drawText(hdc uintptr, s string, x1, y1, x2, y2 int, flags uintptr) {
	if s == "" {
		return
	}
	p := utf16(s)
	r := [4]int32{int32(x1), int32(y1), int32(x2), int32(y2)}
	procDrawText.Call(hdc, uintptr(unsafe.Pointer(p)), ^uintptr(0),
		uintptr(unsafe.Pointer(&r[0])), flags)
	runtime.KeepAlive(p)
}

func fillRect(hdc uintptr, x1, y1, x2, y2 int, brush uintptr) {
	r := [4]int32{int32(x1), int32(y1), int32(x2), int32(y2)}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r[0])), brush)
}

// ── Window procedure ──────────────────────────────────────────────────────────

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {

	case WM_CREATE:
		// Brushes
		hdrBrush, _, _ = procCreateSolidBrush.Call(colHdrBg)
		bodyBrush, _, _ = procCreateSolidBrush.Call(colBodyBg)
		surfBrush, _, _ = procCreateSolidBrush.Call(colSurface)
		logBrush, _, _ = procCreateSolidBrush.Call(colLogBg)
		// Fonts
		hFont = mkFont(15, 400, "Segoe UI")
		hFontBold = mkFont(15, 700, "Segoe UI")
		hFontSmall = mkFont(12, 400, "Segoe UI")
		hFontSection = mkFont(11, 700, "Segoe UI")
		hFontTitle = mkFont(20, 700, "Segoe UI")
		hFontSub = mkFont(13, 400, "Segoe UI")
		hFontBadge = mkFont(11, 700, "Segoe UI")
		hFontMono = mkFont(13, 400, "Consolas")
		createControls(hwnd)
		return 0

	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			paintWindow(hdc)
		}
		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case WM_DRAWITEM:
		if dis := (*DRAWITEMSTRUCT)(unsafe.Pointer(lParam)); dis != nil {
			drawButton(dis)
		}
		return 1

	case WM_CTLCOLORSTATIC:
		// All STATIC labels: transparent over body bg, muted text.
		procSetBkMode.Call(wParam, TRANSPARENT)
		procSetTextColor.Call(wParam, colTextMut)
		return bodyBrush

	case WM_CTLCOLOREDIT:
		// Log edit: darkest bg, muted text (monospace terminal feel).
		if lParam == hStatus {
			procSetBkColor.Call(wParam, colLogBg)
			procSetTextColor.Call(wParam, colTextMut)
			return logBrush
		}
		// Input fields: dark surface, primary text.
		procSetBkColor.Call(wParam, colSurface)
		procSetTextColor.Call(wParam, colTextPri)
		return surfBrush

	case WM_COMMAND:
		id := wParam & 0xFFFF
		switch id {
		case IDC_INSTALL:
			if !installing {
				go runInstall()
			}
		case IDC_CANCEL:
			procDestroyWindow.Call(hwnd)
		}
		return 0

	case WM_DESTROY:
		for _, h := range []uintptr{
			hdrBrush, bodyBrush, surfBrush, logBrush,
			hFont, hFontBold, hFontSmall, hFontSection,
			hFontTitle, hFontSub, hFontBadge, hFontMono,
		} {
			procDeleteObject.Call(h)
		}
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wParam, lParam)
	return r
}

// ── Paint ──────────────────────────────────────────────────────────────────────

func paintWindow(hdc uintptr) {
	nullPen, _, _ := procGetStockObject.Call(NULL_PEN)

	// ── Body fill ─────────────────────────────────────────────────────────────
	fillRect(hdc, 0, 0, WINW, WINH, bodyBrush)

	// ── Header fill ───────────────────────────────────────────────────────────
	fillRect(hdc, 0, 0, WINW, HDR, hdrBrush)

	// Left accent bar (4px, full header height)
	accentBrush, _, _ := procCreateSolidBrush.Call(colAccent)
	fillRect(hdc, 0, 0, 4, HDR, accentBrush)
	procDeleteObject.Call(accentBrush)

	// Bottom accent line under header (2px)
	accPen, _, _ := procCreatePen.Call(0, 2, colAccent)
	procSelectObject.Call(hdc, accPen)
	procMoveToEx.Call(hdc, 0, uintptr(HDR-1), 0)
	procLineTo.Call(hdc, WINW, uintptr(HDR-1))
	procSelectObject.Call(hdc, nullPen)
	procDeleteObject.Call(accPen)

	procSetBkMode.Call(hdc, TRANSPARENT)

	// ── Header typography ─────────────────────────────────────────────────────
	// Product word-mark
	procSelectObject.Call(hdc, hFontTitle)
	procSetTextColor.Call(hdc, colWhite)
	drawText(hdc, "Audspect", LPAD+8, 13, 300, 44, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)

	// Subtitle
	procSelectObject.Call(hdc, hFontSub)
	procSetTextColor.Call(hdc, colTextMut)
	drawText(hdc, "Breach & Attack Simulation Platform", LPAD+8, 48, WINW-LPAD, 70, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)

	// Badge: "AGENT SETUP" right-aligned in accent blue
	procSelectObject.Call(hdc, hFontBadge)
	procSetTextColor.Call(hdc, colAccent)
	drawText(hdc, "AGENT SETUP", 0, 13, WINW-LPAD, 36, DT_RIGHT|DT_SINGLELINE|DT_NOCLIP)

	// ── Body section headers ───────────────────────────────────────────────────
	procSelectObject.Call(hdc, hFontSection)
	procSetTextColor.Call(hdc, colTextMut)
	drawText(hdc, "CONFIGURATION", LPAD, ySec1, WINW-LPAD, ySec1+16, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
	drawText(hdc, "INSTALLATION LOG", LPAD, ySec2, WINW-LPAD, ySec2+16, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)

	// ── Field labels (drawn here, not STATIC controls, for consistent colour) ─
	procSelectObject.Call(hdc, hFontSmall)
	procSetTextColor.Call(hdc, colTextMut)
	drawText(hdc, "Server URL", LPAD, yURLLbl, WINW-LPAD, yURLLbl+16, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
	drawText(hdc, "Agent Secret", LPAD, ySecLbl, WINW-LPAD, ySecLbl+16, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
	drawText(hdc, "Environment Label", LPAD, yEnvLbl, WINW-LPAD, yEnvLbl+16, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)

	// ── Divider between config and log sections ────────────────────────────────
	divPen, _, _ := procCreatePen.Call(0, 1, colBorder)
	procSelectObject.Call(hdc, divPen)
	procMoveToEx.Call(hdc, LPAD, uintptr(yDivider), 0)
	procLineTo.Call(hdc, WINW-LPAD, uintptr(yDivider))
	procSelectObject.Call(hdc, nullPen)
	procDeleteObject.Call(divPen)
}

// drawButton paints an owner-drawn button (WM_DRAWITEM).
// Primary (IDC_INSTALL): accent blue fill, white bold text.
// Secondary (IDC_CANCEL): dark surface fill, muted text, border.
func drawButton(dis *DRAWITEMSTRUCT) {
	pressed := (dis.ItemState & ODS_SELECTED) != 0
	rc := dis.RcItem // copy to local so &rc[0] is a normal Go pointer
	l, t, r, b := int(rc[0]), int(rc[1]), int(rc[2]), int(rc[3])
	nullPen, _, _ := procGetStockObject.Call(NULL_PEN)

	if dis.CtlID == IDC_INSTALL {
		// Blue primary button.
		bg := colAccent
		if pressed {
			bg = colAccentPrs
		}
		brush, _, _ := procCreateSolidBrush.Call(bg)
		pen, _, _ := procCreatePen.Call(0, 1, bg)
		procSelectObject.Call(dis.HDC, brush)
		procSelectObject.Call(dis.HDC, pen)
		procRoundRect.Call(dis.HDC,
			uintptr(l), uintptr(t), uintptr(r), uintptr(b), 8, 8)
		procDeleteObject.Call(brush)
		procDeleteObject.Call(pen)

		procSetBkMode.Call(dis.HDC, TRANSPARENT)
		procSetTextColor.Call(dis.HDC, colWhite)
		procSelectObject.Call(dis.HDC, hFontBold)
		p := utf16("Validate & Install")
		procDrawText.Call(dis.HDC, uintptr(unsafe.Pointer(p)), ^uintptr(0),
			uintptr(unsafe.Pointer(&rc[0])),
			DT_CENTER|DT_VCENTER|DT_SINGLELINE)
		runtime.KeepAlive(p)
	} else {
		// Dark secondary button with muted border.
		bg := colSurface
		if pressed {
			bg = colBorder
		}
		brush, _, _ := procCreateSolidBrush.Call(bg)
		borderPen, _, _ := procCreatePen.Call(0, 1, colBorder)
		procSelectObject.Call(dis.HDC, brush)
		procSelectObject.Call(dis.HDC, borderPen)
		procRoundRect.Call(dis.HDC,
			uintptr(l), uintptr(t), uintptr(r), uintptr(b), 8, 8)
		procDeleteObject.Call(brush)
		procDeleteObject.Call(borderPen)
		procSelectObject.Call(dis.HDC, nullPen)

		procSetBkMode.Call(dis.HDC, TRANSPARENT)
		procSetTextColor.Call(dis.HDC, colTextMut)
		procSelectObject.Call(dis.HDC, hFont)
		p := utf16("Exit")
		procDrawText.Call(dis.HDC, uintptr(unsafe.Pointer(p)), ^uintptr(0),
			uintptr(unsafe.Pointer(&rc[0])),
			DT_CENTER|DT_VCENTER|DT_SINGLELINE)
		runtime.KeepAlive(p)
	}
}

// ── Control creation ──────────────────────────────────────────────────────────

func createControls(hwnd uintptr) {
	// Field labels are now painted in WM_PAINT (drawText) for consistent dark
	// styling — STATIC controls inherit the system theme and are hard to fully
	// dark-theme without subclassing, so we skip them here.

	mkEdit := func(id, x, y, w, h int, style uint32) uintptr {
		hw := createCtl(0, "EDIT", "",
			WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|style,
			x, y, w, h, hwnd, uintptr(id), hInst)
		setFont(hw, hFont)
		return hw
	}

	hURLEdit = mkEdit(IDC_URL, LPAD, yURLEdit, FW, EDTH, ES_LEFT)
	setWindowText(hURLEdit, "http://")

	hSecEdit = mkEdit(IDC_SECRET, LPAD, ySecEdit, FW, EDTH, ES_PASSWORD)

	hEnvEdit = mkEdit(IDC_ENV, LPAD, yEnvEdit, FW, EDTH, ES_LEFT)
	setWindowText(hEnvEdit, "Production")

	// Log area — dark terminal style, monospace.
	hStatus = createCtl(0, "EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		LPAD, yLog, FW, logH, hwnd, uintptr(IDC_STATUS), hInst)
	setFont(hStatus, hFontMono)

	// Primary button: BS_OWNERDRAW so we can paint it accent blue.
	hInstBtn = createCtl(0, "BUTTON", "Validate & Install",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,
		LPAD, yBtns, 196, 34, hwnd, uintptr(IDC_INSTALL), hInst)

	// Secondary button.
	hCancelBtn = createCtl(0, "BUTTON", "Exit",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,
		LPAD+206, yBtns, 76, 34, hwnd, uintptr(IDC_CANCEL), hInst)
}

// ── Install logic ─────────────────────────────────────────────────────────────

func runInstall() {
	installing = true
	procEnableWindow.Call(hInstBtn, 0)

	serverURL := getWindowText(hURLEdit)
	secret := getWindowText(hSecEdit)
	envLabel := getWindowText(hEnvEdit)

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

	appendStatus("[1/4] Validating server connectivity and secret...")
	if err := validateEnrollment(serverURL, secret); err != nil {
		appendStatus("[ERROR] " + err.Error())
		appendStatus("       Check the Server URL and Agent Secret, then try again.")
		procEnableWindow.Call(hInstBtn, 1)
		installing = false
		return
	}
	appendStatus("[1/4] Server validated OK.")

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

	appendStatus("[3/4] Installing BASAgent service...")
	cmd := exec.Command(agentPath,
		"--install",
		"--server", serverURL,
		"--env", envLabel,
		"--secret", secret,
	)
	cmd.Dir = installDir
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
	for _, line := range splitLines(string(out)) {
		if line != "" {
			appendStatus("        " + line)
		}
	}

	appendStatus("[4/4] Starting BASAgent service...")
	sc := exec.Command("sc", "start", "BASAgent")
	sc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	scOut, scErr := sc.CombinedOutput()
	if scErr != nil {
		appendStatus("[~] sc start: " + string(scOut))
	}

	ensureWebView2Runtime()

	if err := registerTrayStartup(agentPath); err != nil {
		appendStatus("[~] Could not register status monitor for startup: " + err.Error())
	} else {
		appendStatus("[+] Status monitor registered to start at login.")
	}
	launchTray(agentPath)

	appendStatus("")
	appendStatus("──────────────────────────────────────────")
	appendStatus("  BAS Agent installed and started.")
	appendStatus("  The agent will enroll in the dashboard")
	appendStatus("  within 30 seconds.")
	appendStatus("  Status monitor icon will appear in tray.")
	appendStatus("──────────────────────────────────────────")

	setWindowText(hInstBtn, "Installed")
	setWindowText(hCancelBtn, "Close")
	procInvalidateRect.Call(hInstBtn, 0, 1)
	procInvalidateRect.Call(hCancelBtn, 0, 1)
	installing = false
}

func registerTrayStartup(agentPath string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("BASAgentTray", `"`+agentPath+`" --tray`)
}

func launchTray(agentPath string) {
	cmd := exec.Command(agentPath, "--tray")
	cmd.Dir = filepath.Dir(agentPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}

const webView2RuntimeClientGUID = `{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

func webView2Installed() bool {
	checks := []struct {
		root registry.Key
		sub  string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + webView2RuntimeClientGUID},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webView2RuntimeClientGUID},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webView2RuntimeClientGUID},
	}
	for _, c := range checks {
		k, err := registry.OpenKey(c.root, c.sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		pv, _, err := k.GetStringValue("pv")
		k.Close()
		if err == nil && pv != "" && pv != "0.0.0.0" {
			return true
		}
	}
	return false
}

func ensureWebView2Runtime() {
	if webView2Installed() {
		appendStatus("[+] WebView2 runtime present.")
		return
	}
	if len(webview2RuntimeInstaller) == 0 {
		appendStatus("[~] WebView2 runtime missing and not bundled — status console will open in browser.")
		return
	}
	appendStatus("[*] Installing Microsoft Edge WebView2 runtime...")
	tmp := filepath.Join(os.TempDir(), "MicrosoftEdgeWebView2RuntimeInstaller.exe")
	if err := os.WriteFile(tmp, webview2RuntimeInstaller, 0755); err != nil {
		appendStatus("[~] Could not stage WebView2 installer: " + err.Error())
		return
	}
	defer os.Remove(tmp)
	cmd := exec.Command(tmp, "/silent", "/install")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		appendStatus("[~] WebView2 runtime install failed: " + err.Error())
		if len(out) > 0 {
			appendStatus("        " + string(out))
		}
		return
	}
	appendStatus("[+] WebView2 runtime installed.")
}

func validateEnrollment(serverURL, secret string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, serverURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach server at %s — check URL and firewall", serverURL)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server health check returned HTTP %d", resp.StatusCode)
	}
	req2, err := http.NewRequest(http.MethodGet, serverURL+"/ws/agent", nil)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	req2.Header.Set("X-Agent-Token", secret)
	resp2, err := client.Do(req2)
	if err != nil {
		return fmt.Errorf("token check failed — cannot reach %s/ws/agent", serverURL)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("agent secret rejected (HTTP 401) — check AGENT_SECRET on the server")
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
	runtime.LockOSThread()

	if !isElevated() {
		procMessageBox.Call(0,
			uintptr(unsafe.Pointer(utf16("This installer requires Administrator privileges.\n\nRight-click the file and choose \"Run as administrator\"."))),
			uintptr(unsafe.Pointer(utf16("Audspect BAS — Agent Setup"))),
			0x10 /*MB_ICONERROR*/)
		return
	}

	hInst, _, _ = procGetModuleHandle.Call(0)

	className := utf16("AudspectInstallerWnd")
	wc := WNDCLASSEX{
		Size:    uint32(unsafe.Sizeof(WNDCLASSEX{})),
		WndProc: wndProcCB,
		Instance: hInst,
		ClassName: className,
	}
	wc.Cursor, _, _ = procLoadCursor.Call(0, 32512 /*IDC_ARROW*/)
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	style := uint32(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE)
	hMainWnd = createCtl(0, "AudspectInstallerWnd",
		"Audspect BAS Platform — Agent Setup",
		style, 0, 0, WINW, WINH, 0, 0, hInst)
	if hMainWnd == 0 {
		procMessageBox.Call(0,
			uintptr(unsafe.Pointer(utf16("Failed to create installer window.\n\nThe installer may already be running."))),
			uintptr(unsafe.Pointer(utf16("Audspect BAS — Agent Setup"))),
			0x10)
		return
	}

	// Centre on screen.
	sw, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	sh, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
	procSetWindowPos.Call(hMainWnd, 0,
		uintptr(int(sw-WINW)/2), uintptr(int(sh-WINH)/2), WINW, WINH,
		0x0040 /*SWP_SHOWWINDOW*/)

	procShowWindow.Call(hMainWnd, SW_SHOW)
	procUpdateWindow.Call(hMainWnd)

	var msg MSG
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 || r == ^uintptr(0) {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// ── UAC elevation ─────────────────────────────────────────────────────────────

var (
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteW")
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
