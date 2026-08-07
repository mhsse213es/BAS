//go:build windows

package main

// browserWindow implements StatusWindow by opening the existing HTML
// status page (ui_dashboard.html, served by local_api_windows.go's "/"
// route -- both unmodified) in the user's default browser. Used as the
// fallback when windigoWindow fails to create its native window.
//
// Refresh is a no-op: the HTML page polls itself via its own embedded JS,
// same as it always has -- this implementation exists only to give the
// fallback path the same Show/Close/Refresh shape StatusController expects
// from any StatusWindow, not to actively drive the browser tab.
type browserWindow struct {
	token string
}

func newBrowserWindow(token string) *browserWindow {
	return &browserWindow{token: token}
}

func (b *browserWindow) Show() error {
	url := "http://127.0.0.1:9001/"
	if b.token != "" {
		url += "?t=" + b.token
	}
	openInBrowser(url)
	return nil
}

func (b *browserWindow) Close() {}

func (b *browserWindow) Refresh(_ StatusSnapshot) {}
