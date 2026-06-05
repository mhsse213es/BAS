//go:build windows && !webview2bundled

package main

// webview2RuntimeInstaller is empty unless the installer is built with
// -tags webview2bundled and the Evergreen Standalone Installer is present at
// webview2/MicrosoftEdgeWebView2RuntimeInstaller.exe. In non-bundled builds the
// agent status console falls back to the browser on machines that lack the
// WebView2 runtime (see installer logic in main.go: ensureWebView2Runtime).
var webview2RuntimeInstaller []byte
