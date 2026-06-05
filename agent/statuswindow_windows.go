//go:build windows

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// runStatusWindow opens the WebView2 status console pointed at the agent's local
// HTTP server. It runs in the user session (unprivileged) and blocks until the
// window is closed. Invoked via `bas_agent.exe --status-window`.
//
// If the WebView2 runtime is not installed, NewWithOptions returns nil and we
// fall back to opening the dashboard in the default browser.
func runStatusWindow() {
	token := readAPIToken()
	url := "http://127.0.0.1:9001/"
	if token != "" {
		url += "?t=" + token
	}

	const winW, winH = 1060, 780
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: "Audspect BAS Agent",
			Width: winW,
			// The library centers with unsigned math against the full screen
			// (ignoring the taskbar), so on small / DPI-scaled client displays a
			// tall window's title bar lands above y=0 and becomes unreachable.
			// We disable its centering and place the window ourselves below.
			Height: winH,
			Center: false,
		},
	})
	if w == nil {
		log.Println("[!] WebView2 runtime unavailable — opening dashboard in browser")
		openInBrowser(url)
		return
	}
	defer w.Destroy()

	// Clamp + center the window inside the monitor work area so the title bar
	// (close / minimize / maximize) is always on-screen regardless of the
	// client's resolution or display scaling.
	fitWindowToWorkArea(uintptr(w.Window()), winW, winH)

	// JS → native bridge. These run in this user-session process so they can
	// write to the user's Desktop and open the user's browser.
	w.Bind("basExport", func() string {
		path, err := exportDiagnosticBundle()
		if err != nil {
			log.Printf("[!] export bundle: %v", err)
			return ""
		}
		// Reveal the bundle in Explorer.
		revealInExplorer(path)
		return path
	})
	w.Bind("basOpenDashboard", func(serverURL string) {
		if serverURL != "" {
			openInBrowser(serverURL)
		}
	})

	w.Navigate(url)
	w.Run()
}

type winRect struct{ Left, Top, Right, Bottom int32 }

// fitWindowToWorkArea resizes the window to fit within the primary monitor's
// work area (the screen minus the taskbar) and centers it there, ensuring the
// title bar is never positioned off-screen on small or DPI-scaled displays.
func fitWindowToWorkArea(hwnd uintptr, desiredW, desiredH int32) {
	if hwnd == 0 {
		return
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	var wa winRect
	const spiGetWorkArea = 0x0030
	r, _, _ := user32.NewProc("SystemParametersInfoW").Call(
		spiGetWorkArea, 0, uintptr(unsafe.Pointer(&wa)), 0,
	)
	if r == 0 {
		return
	}
	workW := wa.Right - wa.Left
	workH := wa.Bottom - wa.Top
	w, h := desiredW, desiredH
	if w > workW {
		w = workW
	}
	if h > workH {
		h = workH
	}
	x := wa.Left + (workW-w)/2
	y := wa.Top + (workH-h)/2
	if x < wa.Left {
		x = wa.Left
	}
	if y < wa.Top {
		y = wa.Top
	}
	const swpNoZorder, swpFrameChanged = 0x0004, 0x0020
	user32.NewProc("SetWindowPos").Call(
		hwnd, 0,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		swpNoZorder|swpFrameChanged,
	)
	user32.NewProc("SetForegroundWindow").Call(hwnd)
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
