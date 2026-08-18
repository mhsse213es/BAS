//go:build windows

package main

import (
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Window dimensions ─────────────────────────────────────────────────────────

const (
	statusWinW = 560
	statusWinH = 720 // total window height (includes title bar ~30px)

	hdrH = 72 // header height
	pad  = 14 // left/right margin
)

// Y positions for each section (client coordinates, ~690px available)
const (
	yStatus    = hdrH + 8
	yOp        = yStatus + 82
	yControls  = yOp + 68
	yEvidence  = yControls + 104
	ySelfProt  = yEvidence + 62
	yResources = ySelfProt + 58
	yActivity  = yResources + 48  // section label at this y
	yButtons   = 638              // button row top (activity edit ends at 630)
)

// ── Color constants (Win32 COLORREF = 0x00BBGGRR) ────────────────────────────

const (
	clrNavyBg   = uintptr(0x0020140b) // header dark navy
	clrNavyText = uintptr(0x00f0e8d0) // off-white header text
	clrBodyBg   = uintptr(0x00f5f5f5) // light gray body
	clrSection  = uintptr(0x00886644) // section header text (muted navy)
	clrLabel    = uintptr(0x00666666) // field label text
	clrValue    = uintptr(0x00111111) // field value text
	clrGreen    = uintptr(0x00368623) // #238636 — healthy indicator
	clrRed      = uintptr(0x003336da) // #da3633 — unhealthy indicator
	clrAmber    = uintptr(0x002299d2) // #d29922 — warning indicator
	clrGray     = uintptr(0x00bbbbbb) // inactive indicator
	clrDivider  = uintptr(0x00dddddd) // section divider line
	clrWhite    = uintptr(0x00ffffff)
)

// ── Win32 GDI procs (window-specific) ────────────────────────────────────────

var (
	gdi32 = windows.NewLazySystemDLL("gdi32.dll")

	procBeginPaint      = user32.NewProc("BeginPaint")
	procEndPaint        = user32.NewProc("EndPaint")
	procFillRect        = user32.NewProc("FillRect")
	procDrawTextW       = user32.NewProc("DrawTextW")
	procSetBkMode       = gdi32.NewProc("SetBkMode")
	procSetTextColor    = gdi32.NewProc("SetTextColor")
	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject    = gdi32.NewProc("DeleteObject")
	procSelectObject    = gdi32.NewProc("SelectObject")
	procCreateFontW     = gdi32.NewProc("CreateFontW")
	procEllipse         = gdi32.NewProc("Ellipse")
	procCreatePen       = gdi32.NewProc("CreatePen")
	procMoveToEx        = gdi32.NewProc("MoveToEx")
	procLineTo          = gdi32.NewProc("LineTo")
	procGetStockObject  = gdi32.NewProc("GetStockObject")
	procSendMessageW    = user32.NewProc("SendMessageW")
	procSetWindowTextW  = user32.NewProc("SetWindowTextW")
	procInvalidateRect  = user32.NewProc("InvalidateRect")
	procEnableWindow    = user32.NewProc("EnableWindow")
	procUpdateWindow    = user32.NewProc("UpdateWindow")
)

const (
	WM_PAINT          = 0x000F
	WM_CREATE         = 0x0001
	WM_CTLCOLORSTATIC = 0x0138
	WM_SETFONT        = 0x0030
	WS_CHILD          = 0x40000000
	WS_VISIBLE        = 0x10000000
	WS_BORDER         = 0x00800000
	WS_TABSTOP        = 0x00010000
	WS_VSCROLL        = 0x00200000
	ES_LEFT           = 0x0000
	ES_MULTILINE      = 0x0004
	ES_AUTOVSCROLL    = 0x0040
	ES_READONLY       = 0x0800
	BS_PUSHBUTTON     = 0x00000000
	BS_DEFPUSHBUTTON  = 0x00000001
	DT_LEFT           = 0x00000000
	DT_CENTER         = 0x00000001
	DT_RIGHT          = 0x00000002
	DT_VCENTER        = 0x00000004
	DT_SINGLELINE     = 0x00000020
	DT_NOCLIP         = 0x00000100
	TRANSPARENT       = 1
	SM_CXSCREEN       = 0
	SM_CYSCREEN       = 1
	SWP_NOMOVE        = 0x0002

	IDC_REFRESH    = 301
	IDC_EXPORT     = 302
	IDC_DASHBOARD  = 303
	IDC_ACTIVITY   = 304
)

// ── Paint structs ─────────────────────────────────────────────────────────────

type paintStruct struct {
	Hdc       uintptr
	Erase     int32
	RcPaint   [4]int32
	Restore   int32
	IncUpdate int32
	Reserved  [32]byte
}

// ── Global window state ───────────────────────────────────────────────────────

var (
	wFont      uintptr
	wFontBold  uintptr
	wFontSmall uintptr
	wHdrBrush  uintptr
	wBodyBrush uintptr
	hActivityEdit uintptr
	hBtnRefresh, hBtnExport, hBtnDashboard uintptr

	windowWndCB = windows.NewCallback(windowWndProc)
)

// ── Status window creation ────────────────────────────────────────────────────

func createStatusWindow() {
	clsName := windows.StringToUTF16Ptr("BASAgentStatusWnd")
	wc := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		Style:     CS_HREDRAW | CS_VREDRAW,
		WndProc:   windowWndCB,
		Instance:  hInst,
		ClassName: clsName,
	}
	wc.Cursor, _, _ = procLoadImageW.Call(0, 32512 /*IDC_ARROW*/, IMAGE_ICON, 0, 0, LR_SHARED)
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	title := windows.StringToUTF16Ptr("Audspect BAS Agent Status")
	style := uint32(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX)
	statusWndHandle, _, _ = procCreateWindowExW.Call(
		0x00000200, /*WS_EX_CLIENTEDGE not wanted; use 0*/
		uintptr(unsafe.Pointer(clsName)),
		uintptr(unsafe.Pointer(title)),
		uintptr(style),
		100, 100, statusWinW, statusWinH,
		0, 0, hInst, 0,
	)
	// Don't show yet — stays hidden until user clicks tray.
}

// ── Window procedure ──────────────────────────────────────────────────────────

func windowWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	// A panic inside a Win32 callback terminates the whole process silently.
	// Recover so a painting/data glitch never kills the tray.
	defer func() {
		if r := recover(); r != nil {
			dbg(fmt.Sprintf("PANIC in windowWndProc msg=0x%X: %v", msg, r))
		}
	}()

	switch uint32(msg) {

	case WM_CREATE:
		wBodyBrush, _, _ = procCreateSolidBrush.Call(clrBodyBg)
		wHdrBrush, _, _ = procCreateSolidBrush.Call(clrNavyBg)
		segoe := windows.StringToUTF16Ptr("Segoe UI")
		wFont, _, _ = procCreateFontW.Call(14, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(segoe)))
		wFontBold, _, _ = procCreateFontW.Call(14, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(segoe)))
		wFontSmall, _, _ = procCreateFontW.Call(12, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(segoe)))
		runtime.KeepAlive(segoe)
		createWindowControls(hwnd)
		return 0

	case WM_PAINT:
		var ps paintStruct
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			paintWindow(hdc)
		}
		procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case WM_CTLCOLORSTATIC:
		procSetBkMode.Call(wParam, TRANSPARENT)
		procSetTextColor.Call(wParam, clrValue)
		return wBodyBrush

	case WM_COMMAND:
		id := wParam & 0xFFFF
		switch id {
		case IDC_REFRESH:
			if apiCli != nil {
				go func() {
					d := apiCli.fetchAll()
					dataMu.Lock()
					curData = d
					dataMu.Unlock()
					procPostMessage.Call(msgWnd, WM_APP_REFRESH, 0, 0)
				}()
			}
		case IDC_EXPORT:
			procPostMessage.Call(msgWnd, WM_COMMAND, IDM_EXPORT, 0)
		case IDC_DASHBOARD:
			procPostMessage.Call(msgWnd, WM_COMMAND, IDM_DASHBOARD, 0)
		}
		return 0

	case WM_CLOSE:
		// Hide instead of destroy.
		procShowWindow.Call(hwnd, SW_HIDE)
		return 0

	case WM_DESTROY:
		procDeleteObject.Call(wFont)
		procDeleteObject.Call(wFontBold)
		procDeleteObject.Call(wFontSmall)
		procDeleteObject.Call(wHdrBrush)
		procDeleteObject.Call(wBodyBrush)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

// Persistent UTF16 pointers — package-level so the GC never frees them while
// Win32 holds references during/after window creation. Returning a uintptr from
// a helper (the old strPtr) lost the reference and could crash on GC.
var (
	clsEDIT      = windows.StringToUTF16Ptr("EDIT")
	clsBUTTON    = windows.StringToUTF16Ptr("BUTTON")
	lblEmpty     = windows.StringToUTF16Ptr("")
	lblRefresh   = windows.StringToUTF16Ptr("  Refresh  ")
	lblExport    = windows.StringToUTF16Ptr("  Export Bundle  ")
	lblDashboard = windows.StringToUTF16Ptr("  Open Dashboard  ")
)

func createWindowControls(hwnd uintptr) {
	fw := uintptr(statusWinW - pad*2) // usable width

	// Activity log — from yActivity+18 to yButtons-8 (leaves gap before buttons)
	actEditH := uintptr(yButtons - (yActivity + 18) - 8)
	hActivityEdit, _, _ = procCreateWindowExW.Call(
		0x200, /*WS_EX_CLIENTEDGE*/
		uintptr(unsafe.Pointer(clsEDIT)), uintptr(unsafe.Pointer(lblEmpty)),
		WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
		pad, yActivity+18, fw, actEditH,
		hwnd, IDC_ACTIVITY, hInst, 0,
	)
	sendFont(hActivityEdit, wFontSmall)

	// Buttons
	btnY := uintptr(yButtons)
	hBtnRefresh, _, _ = procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(clsBUTTON)), uintptr(unsafe.Pointer(lblRefresh)),
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		pad, btnY, 90, 30, hwnd, IDC_REFRESH, hInst, 0)
	sendFont(hBtnRefresh, wFont)

	hBtnExport, _, _ = procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(clsBUTTON)), uintptr(unsafe.Pointer(lblExport)),
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		pad+100, btnY, 140, 30, hwnd, IDC_EXPORT, hInst, 0)
	sendFont(hBtnExport, wFont)

	hBtnDashboard, _, _ = procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(clsBUTTON)), uintptr(unsafe.Pointer(lblDashboard)),
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,
		pad+250, btnY, 150, 30, hwnd, IDC_DASHBOARD, hInst, 0)
	sendFont(hBtnDashboard, wFont)
}

// ── Painting ──────────────────────────────────────────────────────────────────

func paintWindow(hdc uintptr) {
	// Body background
	bodyRect := [4]int32{0, 0, statusWinW, statusWinH}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&bodyRect[0])), wBodyBrush)

	// ── Header ────────────────────────────────────────────────────────────────
	hdrRect := [4]int32{0, 0, statusWinW, hdrH}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&hdrRect[0])), wHdrBrush)

	procSetBkMode.Call(hdc, TRANSPARENT)

	// Status badge (right side of header)
	dataMu.RLock()
	d := curData
	dataMu.RUnlock()

	badge, badgeClr := statusBadge(d)
	segoeTitle := windows.StringToUTF16Ptr("Segoe UI")
	titleFont, _, _ := procCreateFontW.Call(19, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(segoeTitle)))
	runtime.KeepAlive(segoeTitle)
	procSelectObject.Call(hdc, titleFont)
	procSetTextColor.Call(hdc, clrNavyText)
	drawText(hdc, "Audspect BAS Agent", pad, 12, statusWinW-pad, 40, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)

	segoeSub := windows.StringToUTF16Ptr("Segoe UI")
	subFont, _, _ := procCreateFontW.Call(12, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(segoeSub)))
	runtime.KeepAlive(segoeSub)
	procSelectObject.Call(hdc, subFont)
	procSetTextColor.Call(hdc, clrGray)
	ver := "v?"
	if d != nil && d.Status != nil {
		ver = "v" + d.Status.AgentVersion
	}
	drawText(hdc, "Breach & Attack Simulation Agent  "+ver, pad, 42, statusWinW-pad, 62, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)

	// Badge text (top-right corner of header)
	procSelectObject.Call(hdc, titleFont)
	procSetTextColor.Call(hdc, badgeClr)
	drawText(hdc, "● "+badge, statusWinW/2, 12, statusWinW-pad, 40, DT_RIGHT|DT_SINGLELINE|DT_NOCLIP)

	procDeleteObject.Call(titleFont)
	procDeleteObject.Call(subFont)

	// ── Sections ──────────────────────────────────────────────────────────────
	paintStatusSection(hdc, d)
	paintOperationSection(hdc, d)
	paintControlsSection(hdc, d)
	paintEvidenceSection(hdc, d)
	paintSelfProtSection(hdc, d)
	paintResourcesSection(hdc, d)
}

// ── Section painters ──────────────────────────────────────────────────────────

func paintStatusSection(hdc uintptr, d *AllData) {
	y := yStatus
	drawSectionHeader(hdc, "STATUS", y)
	y += 18

	var server, state, uptime, heartbeat string
	if d != nil && d.Status != nil && d.Err == nil {
		s := d.Status
		conn := "● Connected"
		if !s.ServerConnected {
			conn = "○ Disconnected"
		}
		server = s.ServerURL + "  " + conn
		if len(s.State) > 0 {
			state = strings.ToUpper(s.State[:1]) + s.State[1:]
		}
		uptime = fmtUptime(s.UptimeSec)
		heartbeat = "–"
		if !s.LastHeartbeat.IsZero() {
			heartbeat = s.LastHeartbeat.Format("15:04:05")
		}
	} else {
		server = "Service not reachable"
		state, uptime, heartbeat = "–", "–", "–"
	}

	drawLabelValue(hdc, "Server:", server, pad, y, 0, 16)
	y += 20
	drawLabelValue2(hdc, "State:", state, "Uptime:", uptime, pad, y)
	y += 20
	drawLabelValue2(hdc, "Heartbeat:", heartbeat, "", "", pad, y)
	drawDivider(hdc, yOp-4)
}

func paintOperationSection(hdc uintptr, d *AllData) {
	y := yOp
	drawSectionHeader(hdc, "CURRENT OPERATION", y)
	y += 18

	var scenarioLine, phaseLine string
	if d != nil && d.Activity != nil {
		if cur := d.Activity.CurrentOperation; cur != nil && cur.Running {
			scenarioLine = cur.ScenarioName
			phaseLine = fmt.Sprintf("%s — %d%%", cur.Phase, cur.Progress)
			if cur.TechniqueID != "" {
				scenarioLine = cur.TechniqueID + "  " + cur.ScenarioName
			}
		} else if last := d.Activity.LastOperation; last != nil {
			elapsed := ""
			if last.CompletedAt != nil {
				elapsed = last.CompletedAt.Format("15:04:05")
			}
			scenarioLine = fmt.Sprintf("Last: %s  %s", last.ScenarioName, last.Result)
			phaseLine = fmt.Sprintf("Completed %s  Duration: %ds", elapsed, last.DurationSec)
		} else {
			scenarioLine = "No simulation history"
			phaseLine = "–"
		}
	} else {
		scenarioLine = "–"
		phaseLine = "–"
	}
	drawLabelValue(hdc, "Scenario:", scenarioLine, pad, y, 0, 16)
	y += 20
	drawLabelValue(hdc, "Phase:", phaseLine, pad, y, 0, 16)
	drawDivider(hdc, yControls-4)
}

func paintControlsSection(hdc uintptr, d *AllData) {
	y := yControls
	drawSectionHeader(hdc, "ENDPOINT SECURITY CONTROLS", y)
	y += 20

	type ctrl struct {
		label string
		ok    bool
		warn  bool // present but degraded
	}
	ctrls := []ctrl{
		{"Defender RTP", false, false},
		{"Sysmon", false, false},
		{"Firewall", false, false},
		{"AppLocker", false, false},
		{"WDAC", false, false},
		{"AMSI", false, false},
	}
	if d != nil && d.Controls != nil {
		c := d.Controls
		ctrls[0].ok = c.Defender.RTPEnabled
		ctrls[0].warn = c.Defender.Present && !c.Defender.RTPEnabled
		ctrls[1].ok = c.Sysmon.Present
		ctrls[2].ok = c.Firewall.Enabled
		ctrls[3].ok = c.AppLocker.Enabled
		ctrls[4].ok = c.WDAC.Enabled
		ctrls[5].ok = c.AMSI.Enabled
	}

	// 3 columns × 2 rows
	colW := (statusWinW - pad*2) / 3
	for i, c := range ctrls {
		col := i % 3
		row := i / 3
		x := pad + col*colW
		iy := y + row*32
		clr := clrGray
		if c.ok {
			clr = clrGreen
		} else if c.warn {
			clr = clrAmber
		} else if c.ok == false && d != nil && d.Controls != nil {
			clr = clrRed
		}
		drawIndicator(hdc, c.label, x, iy, clr)
	}
	drawDivider(hdc, yEvidence-4)
}

func paintEvidenceSection(hdc uintptr, d *AllData) {
	y := yEvidence
	drawSectionHeader(hdc, "EVIDENCE (LAST RUN)", y)
	y += 18

	var events, defender, sysmon, queue string
	if d != nil && d.Evidence != nil {
		e := d.Evidence
		events = fmt.Sprintf("%d", e.EventsCollected)
		defender = fmt.Sprintf("%d", e.DefenderAlerts)
		sysmon = fmt.Sprintf("%d", e.SysmonDetections)
		queue = fmt.Sprintf("%d", e.QueueSize)
	} else {
		events, defender, sysmon, queue = "–", "–", "–", "–"
	}
	drawLabelValue2(hdc, "Events Collected:", events, "Defender Alerts:", defender, pad, y)
	y += 20
	drawLabelValue2(hdc, "Sysmon Detections:", sysmon, "Upload Queue:", queue, pad, y)
	drawDivider(hdc, ySelfProt-4)
}

func paintSelfProtSection(hdc uintptr, d *AllData) {
	y := ySelfProt
	drawSectionHeader(hdc, "SELF-PROTECTION", y)
	y += 18

	type ind struct {
		label string
		ok    bool
	}
	inds := []ind{
		{"Service Running", false},
		{"Policy Sync", false},
		{"Evidence Queue", false},
		{"Last Upload OK", false},
		{"Server Contact", false},
	}
	if d != nil && d.Status != nil {
		s := d.Status
		inds[0].ok = s.ServiceRunning
		inds[1].ok = s.State == "active" || s.State == "restricted"
		inds[2].ok = d.Evidence == nil || d.Evidence.QueueSize < 100
		inds[3].ok = s.LastUploadOk
		inds[4].ok = s.ServerConnected
	}

	colW := (statusWinW - pad*2) / 5
	for i, ind := range inds {
		x := pad + i*colW
		clr := clrGray
		if d != nil && d.Status != nil {
			if ind.ok {
				clr = clrGreen
			} else {
				clr = clrRed
			}
		}
		drawIndicator(hdc, ind.label, x, y, clr)
	}
	drawDivider(hdc, yResources-4)
}

func paintResourcesSection(hdc uintptr, d *AllData) {
	y := yResources
	drawSectionHeader(hdc, "RESOURCES", y)
	y += 18

	cpu := "–"
	ram := "–"
	if d != nil && d.Status != nil {
		ram = fmt.Sprintf("%d MB", d.Status.RAMMB)
	}
	drawLabelValue2(hdc, "CPU:", cpu, "RAM:", ram, pad, y)
}

// ── Drawing helpers ───────────────────────────────────────────────────────────

func drawSectionHeader(hdc uintptr, text string, y int) {
	procSelectObject.Call(hdc, wFontSmall)
	procSetTextColor.Call(hdc, clrSection)
	drawText(hdc, text, pad, y, statusWinW-pad, y+16, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
}

func drawLabelValue(hdc uintptr, label, value string, x, y, _ int, _ int) {
	labelW := 90
	procSelectObject.Call(hdc, wFont)
	procSetTextColor.Call(hdc, clrLabel)
	drawText(hdc, label, x, y, x+labelW, y+18, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
	procSetTextColor.Call(hdc, clrValue)
	drawText(hdc, value, x+labelW+4, y, statusWinW-pad, y+18, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
}

func drawLabelValue2(hdc uintptr, label1, val1, label2, val2 string, x, y int) {
	half := (statusWinW - pad*2) / 2
	lblW := 90
	procSelectObject.Call(hdc, wFont)
	procSetTextColor.Call(hdc, clrLabel)
	drawText(hdc, label1, x, y, x+lblW, y+18, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
	procSetTextColor.Call(hdc, clrValue)
	drawText(hdc, val1, x+lblW+4, y, x+half, y+18, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
	if label2 != "" {
		x2 := x + half + 4
		procSetTextColor.Call(hdc, clrLabel)
		drawText(hdc, label2, x2, y, x2+lblW, y+18, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
		procSetTextColor.Call(hdc, clrValue)
		drawText(hdc, val2, x2+lblW+4, y, statusWinW-pad, y+18, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
	}
}

func drawIndicator(hdc uintptr, label string, x, y int, clr uintptr) {
	// Filled circle (12×12)
	brush, _, _ := procCreateSolidBrush.Call(clr)
	pen, _, _ := procCreatePen.Call(0, 1, clr)
	procSelectObject.Call(hdc, brush)
	procSelectObject.Call(hdc, pen)
	procEllipse.Call(hdc, uintptr(x), uintptr(y+2), uintptr(x+12), uintptr(y+14))
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)
	// Label
	procSelectObject.Call(hdc, wFontSmall)
	procSetTextColor.Call(hdc, clrValue)
	drawText(hdc, label, x+16, y, x+120, y+18, DT_LEFT|DT_SINGLELINE|DT_NOCLIP)
}

func drawDivider(hdc uintptr, y int) {
	pen, _, _ := procCreatePen.Call(0, 1, clrDivider)
	procSelectObject.Call(hdc, pen)
	procMoveToEx.Call(hdc, pad, uintptr(y), 0)
	procLineTo.Call(hdc, statusWinW-pad, uintptr(y))
	procDeleteObject.Call(pen)
}

func drawText(hdc uintptr, s string, x1, y1, x2, y2 int, flags uintptr) {
	if s == "" {
		return
	}
	p := windows.StringToUTF16Ptr(s)
	r := [4]int32{int32(x1), int32(y1), int32(x2), int32(y2)}
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(p)), ^uintptr(0),
		uintptr(unsafe.Pointer(&r[0])), flags)
	runtime.KeepAlive(p)
}

func sendFont(hwnd, font uintptr) {
	procSendMessageW.Call(hwnd, WM_SETFONT, font, 1)
}

// ── Data display update ───────────────────────────────────────────────────────

// updateWindowData refreshes the activity log edit control and invalidates
// the window so WM_PAINT redraws all sections with new data.
func updateWindowData(d *AllData) {
	if statusWndHandle == 0 {
		return
	}
	// Update activity log edit control.
	if hActivityEdit != 0 && d.Activity != nil {
		var sb strings.Builder
		for _, item := range d.Activity.RecentActivity {
			t := item.Time.Format("15:04:05")
			sb.WriteString(t)
			sb.WriteString("  ")
			sb.WriteString(item.Event)
			sb.WriteString("\r\n")
		}
		p := windows.StringToUTF16Ptr(sb.String())
		procSetWindowTextW.Call(hActivityEdit, uintptr(unsafe.Pointer(p)))
		runtime.KeepAlive(p)
	}
	// Trigger repaint.
	procInvalidateRect.Call(statusWndHandle, 0, 1 /*erase*/)
	procUpdateWindow.Call(statusWndHandle)
}

// ── Status badge ──────────────────────────────────────────────────────────────

func statusBadge(d *AllData) (string, uintptr) {
	if d == nil || d.Err != nil || d.Status == nil {
		return "Offline", clrRed
	}
	if !d.Status.ServerConnected {
		return "Disconnected", clrRed
	}
	if d.Status.Status != "idle" {
		return "Simulation Running", clrAmber
	}
	if d.Status.State == "quarantined" {
		return "Quarantined", clrRed
	}
	if d.Status.State == "restricted" {
		return "Restricted", clrAmber
	}
	return "Protected", clrGreen
}

func fmtTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "–"
	}
	return t.Format("15:04:05")
}

var _ = fmtTime // suppress unused warning; may be used in future sections
