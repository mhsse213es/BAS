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

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Audspect BAS Agent",
			Width:  1060,
			Height: 780,
			Center: true,
		},
	})
	if w == nil {
		log.Println("[!] WebView2 runtime unavailable — opening dashboard in browser")
		openInBrowser(url)
		return
	}
	defer w.Destroy()

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
