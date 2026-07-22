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

The runtime is shipped as a **separate file next to `installer.exe`**, not
embedded — embedding it via `go:embed` would balloon `installer.exe` from
~14MB to ~190MB, which this project treats as unacceptable.

- The filename just needs to match the pattern `*WebView2*RuntimeInstaller*.exe`
  (the file Microsoft ships today already does) — not an exact name, so a
  future Microsoft rename doesn't require a BAS code change, just re-dropping
  the renamed file here.
- `packaging/windows-build.ps1` and the Docker build (`orchestrator/Dockerfile`)
  both copy whichever matching file is present here alongside the built
  installer in their output — no build tag, no embedding.
- At install time, the GUI installer looks for that same pattern **only in its
  own directory** (never Downloads/%TEMP%/CWD/%ProgramData%) and runs it
  directly with `/silent /install` if found (see `ensureWebView2Runtime` and
  `findWebView2Installer` in `main.go`). If no match is found, it logs a
  message and the status console falls back to opening in the browser.
