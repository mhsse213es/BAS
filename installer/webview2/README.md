# Bundled Microsoft Edge WebView2 Runtime

The agent's status console is rendered with the **Edge WebView2 Runtime**. On a
machine that lacks the runtime, the console falls back to opening in the default
browser. To give air-gapped client workstations the native window automatically,
the GUI installer can **bundle and silently install** the runtime.

## What to drop here

Download the **Evergreen Standalone Installer (x64)** once from
<https://developer.microsoft.com/microsoft-edge/webview2/> (section
"Evergreen Standalone Installer", architecture **x64**) and place it here as:

```
installer/webview2/MicrosoftEdgeWebView2RuntimeInstaller.exe
```

It is ~170 MB and is **git-ignored** (the repo's recursive `*.exe` rule), so it
is never committed.

## How it is used

- When the file is present, `packaging/windows-build.ps1` and the Docker build
  detect it and compile the installer with `-tags webview2bundled`, embedding it
  (see `installer/webview2_bundled.go`).
- At install time, the GUI installer checks the WebView2 registry key and, if
  the runtime is missing, runs the embedded installer with `/silent /install`
  before launching the tray (see `ensureWebView2Runtime` in `main.go`).
- A bare `go build` (no tag) ignores the file and keeps the browser fallback
  (see `installer/webview2_stub.go`), so the binary is optional for dev builds.
