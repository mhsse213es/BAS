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

	procRegisterClassEx        = user32.NewProc("RegisterClassExW")
	procCreateWindowEx         = user32.NewProc("CreateWindowExW")
	procShowWindow             = user32.NewProc("ShowWindow")
	procUpdateWindow           = user32.NewProc("UpdateWindow")
	procGetMessage             = user32.NewProc("GetMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessage        = user32.NewProc("DispatchMessageW")
	procDefWindowProc          = user32.NewProc("DefWindowProcW")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procDestroyWindow          = user32.NewProc("DestroyWindow")
	procLoadCursor             = user32.NewProc("LoadCursorW")
	procGetWindowText          = user32.NewProc("GetWindowTextW")
	procSetWindowText          = user32.NewProc("SetWindowTextW")
	procSendMessage            = user32.NewProc("SendMessageW")
	procMessageBox             = user32.NewProc("MessageBoxW")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procSetWindowPos           = user32.NewProc("SetWindowPos")
	procBeginPaint             = user32.NewProc("BeginPaint")
	procEndPaint               = user32.NewProc("EndPaint")
	procFillRect               = user32.NewProc("FillRect")
	procDrawText               = user32.NewProc("DrawTextW")
	procEnableWindow           = user32.NewProc("EnableWindow")
	procInvalidateRect         = user32.NewProc("InvalidateRect")
	procSetFocus               = user32.NewProc("SetFocus")
	procGetFocus               = user32.NewProc("GetFocus")
	procIsDialogMessage        = user32.NewProc("IsDialogMessageW")
	procCreateAcceleratorTable = user32.NewProc("CreateAcceleratorTableW")
	procTranslateAccelerator   = user32.NewProc("TranslateAcceleratorW")
	procAdjustWindowRectEx     = user32.NewProc("AdjustWindowRectEx")

	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procCreateFont       = gdi32.NewProc("CreateFontW")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procSetBkMode        = gdi32.NewProc("SetBkMode")
	procSetTextColor     = gdi32.NewProc("SetTextColor")

	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
)

// ── Win32 message / style constants ──────────────────────────────────────────

const (
	WM_CREATE  = 0x0001
	WM_DESTROY = 0x0002
	WM_PAINT   = 0x000F
	WM_COMMAND = 0x0111
	WM_SETFONT = 0x0030

	WS_OVERLAPPED    = 0x00000000
	WS_CAPTION       = 0x00C00000
	WS_SYSMENU       = 0x00080000
	WS_MINIMIZEBOX   = 0x00020000
	WS_VISIBLE       = 0x10000000
	WS_CHILD         = 0x40000000
	WS_BORDER        = 0x00800000
	WS_TABSTOP       = 0x00010000
	WS_GROUP         = 0x00020000
	WS_VSCROLL       = 0x00200000
	ES_LEFT          = 0x0000
	ES_MULTILINE     = 0x0004
	ES_AUTOVSCROLL   = 0x0040
	ES_PASSWORD      = 0x0020
	ES_READONLY      = 0x0800
	SS_LEFT          = 0x00000000
	BS_PUSHBUTTON    = 0x00000000
	BS_DEFPUSHBUTTON = 0x00000001

	SW_SHOW = 5

	SM_CXSCREEN = 0
	SM_CYSCREEN = 1

	DT_LEFT       = 0x00000000
	DT_SINGLELINE = 0x00000020
	DT_NOCLIP     = 0x00000100
	DT_NOPREFIX   = 0x00000800

	COLOR_BTNFACE = 15

	EM_SETSEL = 0x00B1

	FVIRTKEY = 0x01
	FCONTROL = 0x08
)

// ── Control IDs ───────────────────────────────────────────────────────────────

const (
	IDC_URL       = 101
	IDC_SECRET    = 102
	IDC_ENV       = 103
	IDC_INSTALL   = 104
	IDC_CANCEL    = 105
	IDC_STATUS    = 106
	IDC_SELECTALL = 107
)

// ── Window geometry ───────────────────────────────────────────────────────────
//
// Plain, native-looking Windows form: a slim identifying header banner
// followed by an ordinary light-themed body. Sober on purpose — this is the
// first thing an IT admin sees when installing an agent on a production
// endpoint, and an unfamiliar/flashy UI reads as untrustworthy in that
// context.

const (
	WINW = 520
	HDR  = 96            // header banner height (client coords)
	LPAD = 24            // left/right gutter
	FW   = WINW - LPAD*2 // usable field width
	EDTH = 28            // edit control height
)

const (
	yURLLbl  = HDR + 24
	yURLEdit = yURLLbl + 22
	ySecLbl  = yURLEdit + EDTH + 20
	ySecEdit = ySecLbl + 22
	yEnvLbl  = ySecEdit + EDTH + 20
	yEnvEdit = yEnvLbl + 22
	yLogLbl  = yEnvEdit + EDTH + 24
	yLog     = yLogLbl + 22
	logH     = 160
	yBtns    = yLog + logH + 18
	btnH     = 34
	// WINCLIENTH is the CLIENT area height the layout above needs — buttons'
	// bottom edge plus a bottom margin. Must be turned into an outer window
	// size via AdjustWindowRectEx (see main()), not passed to CreateWindowEx
	// directly: CreateWindowEx's height is the OUTER window size (title bar +
	// borders included), so using this raw value there clips the button row.
	WINCLIENTH = yBtns + btnH + 24
)

// ── Colours (Win32 COLORREF = 0x00BBGGRR) ────────────────────────────────────
//
// Only the header banner is custom-painted; every other control uses the
// system's default colours (white edits, light-grey body, native buttons)
// so the window matches the look of any other Windows program.

const (
	colHdrBg  = uintptr(0x0020140B) // dark navy header — brand identifier only
	colWhite  = uintptr(0x00FFFFFF)
	colHdrSub = uintptr(0x00C8C8C8) // neutral light grey subtitle text
)

// ── Win32 structs ─────────────────────────────────────────────────────────────

type WNDCLASSEX struct {
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

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type RECT struct {
	Left, Top, Right, Bottom int32
}

type PAINTSTRUCT struct {
	Hdc       uintptr
	Erase     int32
	RcPaint   [4]int32
	Restore   int32
	IncUpdate int32
	Reserved  [32]byte
}

// ACCEL mirrors the Win32 tagACCEL struct (fVirt:BYTE, pad, key:WORD, cmd:WORD).
type ACCEL struct {
	FVirt byte
	_     byte
	Key   uint16
	Cmd   uint16
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

	hdrBrush uintptr // header banner fill — created once in WM_CREATE

	hFont      uintptr // Segoe UI, regular — edits/buttons
	hFontBold  uintptr // Segoe UI, bold — primary button
	hFontSmall uintptr // Segoe UI, small — field labels
	hFontTitle uintptr // Segoe UI, large bold — header title
	hFontSub   uintptr // Segoe UI, regular — header subtitle
	hFontMono  uintptr // Consolas — log area

	wndProcCB  = syscall.NewCallback(wndProc)
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
		hdrBrush, _, _ = procCreateSolidBrush.Call(colHdrBg)
		hFont = mkFont(15, 400, "Segoe UI")
		hFontBold = mkFont(15, 700, "Segoe UI")
		hFontSmall = mkFont(14, 400, "Segoe UI")
		hFontTitle = mkFont(22, 700, "Segoe UI")
		hFontSub = mkFont(14, 400, "Segoe UI")
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

	case WM_COMMAND:
		id := wParam & 0xFFFF
		switch id {
		case IDC_INSTALL:
			if !installing {
				go runInstall()
			}
		case IDC_CANCEL:
			procDestroyWindow.Call(hwnd)
		case IDC_SELECTALL:
			if f, _, _ := procGetFocus.Call(); f == hURLEdit || f == hSecEdit || f == hEnvEdit || f == hStatus {
				procSendMessage.Call(f, EM_SETSEL, 0, ^uintptr(0))
			}
		}
		return 0

	case WM_DESTROY:
		for _, h := range []uintptr{
			hdrBrush, hFont, hFontBold, hFontSmall, hFontTitle, hFontSub, hFontMono,
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
//
// Only the header banner is hand-painted; the body is left to the window
// class's default background brush and the native controls draw themselves.

func paintWindow(hdc uintptr) {
	fillRect(hdc, 0, 0, WINW, HDR, hdrBrush)
	procSetBkMode.Call(hdc, 1 /*TRANSPARENT*/)

	procSelectObject.Call(hdc, hFontTitle)
	procSetTextColor.Call(hdc, colWhite)
	drawText(hdc, "BAS Platform Agent Setup", LPAD, 22, WINW-LPAD, 52,
		DT_LEFT|DT_SINGLELINE|DT_NOCLIP|DT_NOPREFIX)

	procSelectObject.Call(hdc, hFontSub)
	procSetTextColor.Call(hdc, colHdrSub)
	drawText(hdc, "Breach & Attack Simulation - Audspect Security", LPAD, 58, WINW-LPAD, 80,
		DT_LEFT|DT_SINGLELINE|DT_NOCLIP|DT_NOPREFIX)
}

// ── Control creation ──────────────────────────────────────────────────────────

func createControls(hwnd uintptr) {
	mkLabel := func(text string, x, y, w, h int) uintptr {
		hw := createCtl(0, "STATIC", text, WS_CHILD|WS_VISIBLE|SS_LEFT, x, y, w, h, hwnd, 0, hInst)
		setFont(hw, hFontSmall)
		return hw
	}

	mkEdit := func(id, x, y, w, h int, style uint32, tabstop bool) uintptr {
		wsStyle := uint32(WS_CHILD | WS_VISIBLE | WS_BORDER | style)
		if tabstop {
			wsStyle |= WS_TABSTOP
		}
		hw := createCtl(0, "EDIT", "", wsStyle, x, y, w, h, hwnd, uintptr(id), hInst)
		setFont(hw, hFont)
		return hw
	}

	mkLabel("Server URL  (e.g. http://10.0.0.5:9000)", LPAD, yURLLbl, FW, 18)
	hURLEdit = mkEdit(IDC_URL, LPAD, yURLEdit, FW, EDTH, ES_LEFT, true)
	setWindowText(hURLEdit, "http://")

	mkLabel("Agent Secret", LPAD, ySecLbl, FW, 18)
	hSecEdit = mkEdit(IDC_SECRET, LPAD, ySecEdit, FW, EDTH, ES_PASSWORD, true)

	mkLabel("Environment Label", LPAD, yEnvLbl, FW, 18)
	hEnvEdit = mkEdit(IDC_ENV, LPAD, yEnvEdit, FW, EDTH, ES_LEFT, true)
	setWindowText(hEnvEdit, "Production")

	mkLabel("Installation Log", LPAD, yLogLbl, FW, 18)
	hStatus = mkEdit(IDC_STATUS, LPAD, yLog, FW, logH,
		ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL, true)
	setFont(hStatus, hFontMono)

	hInstBtn = createCtl(0, "BUTTON", "Validate && Install",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_GROUP|BS_DEFPUSHBUTTON,
		LPAD, yBtns, 196, btnH, hwnd, uintptr(IDC_INSTALL), hInst)
	setFont(hInstBtn, hFontBold)

	hCancelBtn = createCtl(0, "BUTTON", "Exit",
		WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
		LPAD+206, yBtns, 76, btnH, hwnd, uintptr(IDC_CANCEL), hInst)
	setFont(hCancelBtn, hFont)
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
		Size:       uint32(unsafe.Sizeof(WNDCLASSEX{})),
		WndProc:    wndProcCB,
		Instance:   hInst,
		ClassName:  className,
		Background: uintptr(COLOR_BTNFACE + 1), // default system light-grey body
	}
	wc.Cursor, _, _ = procLoadCursor.Call(0, 32512 /*IDC_ARROW*/)
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	style := uint32(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE)

	// The layout consts above (yBtns etc.) are CLIENT coordinates, but
	// CreateWindowEx's w/h are OUTER window dimensions — the title bar and
	// borders eat into that. Passing WINCLIENTH straight to CreateWindowEx
	// clipped the bottom button row. AdjustWindowRectEx gives the outer size
	// that actually yields a WINW x WINCLIENTH client area.
	rect := RECT{0, 0, int32(WINW), int32(WINCLIENTH)}
	procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&rect)), uintptr(style), 0, 0)
	outerW := int(rect.Right - rect.Left)
	outerH := int(rect.Bottom - rect.Top)

	hMainWnd = createCtl(0, "AudspectInstallerWnd",
		"BAS Platform - Agent Setup",
		style, 0, 0, outerW, outerH, 0, 0, hInst)
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
	cx := (int(sw) - outerW) / 2
	cy := (int(sh) - outerH) / 2
	procSetWindowPos.Call(hMainWnd, 0,
		uintptr(cx), uintptr(cy), uintptr(outerW), uintptr(outerH),
		0x0040 /*SWP_SHOWWINDOW*/)

	procShowWindow.Call(hMainWnd, SW_SHOW)
	procUpdateWindow.Call(hMainWnd)
	procSetFocus.Call(hURLEdit)

	// Ctrl+A → select-all in whichever field currently has focus. Native EDIT
	// controls don't bind this themselves; only Ctrl+C/V/X are built in.
	accel := []ACCEL{{FVirt: FVIRTKEY | FCONTROL, Key: 'A', Cmd: IDC_SELECTALL}}
	hAccel, _, _ := procCreateAcceleratorTable.Call(uintptr(unsafe.Pointer(&accel[0])), uintptr(len(accel)))

	var msg MSG
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 || r == ^uintptr(0) {
			break
		}
		if h, _, _ := procTranslateAccelerator.Call(hMainWnd, hAccel, uintptr(unsafe.Pointer(&msg))); h != 0 {
			continue
		}
		// IsDialogMessage drives Tab/Shift+Tab focus-cycling across the
		// WS_TABSTOP controls below — this window is a plain CreateWindowEx
		// window, not a real dialog, so nothing does that automatically
		// without this call.
		if h, _, _ := procIsDialogMessage.Call(hMainWnd, uintptr(unsafe.Pointer(&msg))); h != 0 {
			continue
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
