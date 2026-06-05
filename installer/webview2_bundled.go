//go:build windows && webview2bundled

package main

import _ "embed"

// webview2RuntimeInstaller holds the Microsoft Edge WebView2 Runtime
// "Evergreen Standalone Installer" (x64), embedded only when building with
// -tags webview2bundled. The build scripts (windows-build.ps1, Dockerfile)
// add that tag automatically when the file below is present, so a bare
// `go build` (no tag) still compiles without the ~170 MB binary.
//
//go:embed webview2/MicrosoftEdgeWebView2RuntimeInstaller.exe
var webview2RuntimeInstaller []byte
