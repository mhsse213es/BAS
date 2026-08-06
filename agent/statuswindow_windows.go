//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runStatusWindow opens the agent's status console in the user's default
// browser, pointed at the agent's local HTTP server. Invoked via
// `bas_agent.exe --status-window`.
//
// This used to host the console in an embedded WebView2 window instead.
// That was abandoned: WebView2 hosted in a process launched via the
// service's CreateProcessAsUser/WTSQueryUserToken chain (exactly this
// agent's tray -> status-window launch path) reliably created the host
// window but left it permanently invisible (IsWindowVisible false from the
// moment of creation, with no error at any layer) -- confirmed via live
// diagnostic logging against the real production launch path, not a
// synthetic reproduction. This is a known, Microsoft-acknowledged
// limitation of WebView2 under a service-launched/impersonated-token
// session process, not something fixable in this codebase:
// https://github.com/MicrosoftEdge/WebView2Feedback/issues/4850
// https://github.com/MicrosoftEdge/WebView2Feedback/issues/2434 (closed by
// Microsoft as "not planned")
// The default browser has no such limitation and needs no embedding at all.
func runStatusWindow() {
	token := readAPIToken()
	url := "http://127.0.0.1:9001/"
	if token != "" {
		url += "?t=" + token
	}
	openInBrowser(url)
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
