# Remove Dead WebView2 Code Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all leftover WebView2 code, tests, docs, and build-pipeline steps that do nothing anymore, since the agent's runtime WebView2 hosting was already fully removed in an earlier change — the tray already unconditionally opens the status console in the user's default browser.

**Architecture:** Pure deletion/cleanup, no new files, no behavior change. Confirmed via investigation: zero WebView2 SDK dependency or host-binding code exists anywhere in `agent/*.go`, `agent/go.mod`, or `agent/go.sum` — `agent/statuswindow_windows.go`'s `runStatusWindow()` already always calls `openInBrowser()` regardless of whether WebView2 is installed. Everything this plan removes is either dead code that's never reached, or build/install steps that bundle/check for a runtime nothing uses.

**Tech Stack:** Go (installer + agent, both `//go:build windows`), PowerShell (`packaging/windows-build.ps1`), Docker (`orchestrator/Dockerfile`), vanilla JS (`agent/ui_dashboard.html`).

## Global Constraints

- No behavior change — the tray-click-opens-browser flow must work identically before and after this change.
- Do not delete any local file on disk that this session didn't create (e.g. a real `MicrosoftEdgeWebView2RuntimeInstaller.exe` you may have dropped in `installer/webview2/` — it's git-ignored and untracked, so removing the tracked `README.md` from that directory does not touch it).

---

### Task 1: Remove dead WebView2 code, tests, docs, and build steps

**Files:**
- Modify: `installer/main.go` (remove 4 functions + 2 consts, simplify the install-summary messaging)
- Delete: `installer/webview2_test.go`
- Delete: `installer/webview2/README.md`
- Modify: `packaging/windows-build.ps1` (remove the WebView2 sibling-file bundling)
- Modify: `orchestrator/Dockerfile` (remove the WebView2 sibling-file bundling)
- Modify: `agent/platform_windows.go` (fix stale flag description)
- Modify: `agent/tray_windows.go` (fix stale doc comment)
- Modify: `agent/ui_dashboard.html` (remove dead host-binding checks)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed elsewhere — this is a leaf cleanup with no other task depending on it.

- [ ] **Step 1: Remove the WebView2 functions and constants from `installer/main.go`**

In `installer/main.go`, delete (currently lines 602-684):

```go
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

// webView2InstallerGlob matches the Microsoft Edge WebView2 Runtime "Evergreen
// Standalone Installer" filename. A glob (not an exact name) because Microsoft
// has changed this filename before and may again — matching a pattern means a
// future rename doesn't require a BAS code change or rebuild, just re-dropping
// the renamed file in the same spot.
const webView2InstallerGlob = "*WebView2*RuntimeInstaller*.exe"

// findWebView2InstallerIn globs dir for the runtime installer. Returns "" if
// none or more than one match is found — an ambiguous match is treated as
// "not found" rather than guessing which file to run.
func findWebView2InstallerIn(dir string) string {
	matches, err := filepath.Glob(filepath.Join(dir, webView2InstallerGlob))
	if err != nil || len(matches) != 1 {
		return ""
	}
	return matches[0]
}

// findWebView2Installer looks for the runtime installer next to the running
// installer.exe — nowhere else (never Downloads, %TEMP%, the current working
// directory, or %ProgramData%), so behavior is deterministic and this never
// risks executing an unexpected binary from a writable/shared location.
func findWebView2Installer() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return findWebView2InstallerIn(filepath.Dir(exePath))
}

// ensureWebView2Runtime installs the WebView2 runtime if it's missing and a
// sibling installer is present. Returns whether the runtime ends up available
// (already present, or just installed) — the caller surfaces this explicitly
// in the final install summary so the operator isn't left to infer it from an
// early progress line that may have scrolled past.
func ensureWebView2Runtime() bool {
	if webView2Installed() {
		appendStatus("[+] WebView2 runtime present.")
		return true
	}
	installerPath := findWebView2Installer()
	if installerPath == "" {
		appendStatus("[~] WebView2 runtime missing (no runtime installer found next to this installer) — status console will open in browser.")
		return false
	}
	appendStatus("[*] Installing Microsoft Edge WebView2 runtime...")
	cmd := exec.Command(installerPath, "/silent", "/install")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		appendStatus("[~] WebView2 runtime install failed: " + err.Error())
		if len(out) > 0 {
			appendStatus("        " + string(out))
		}
		return false
	}
	appendStatus("[+] WebView2 runtime installed.")
	return true
}
```

Leave everything before line 602 and after line 684 untouched. `registry`, `filepath`, `syscall`, `exec`, and `os` all stay imported — every one of them is used elsewhere in this same file (`registerTrayStartup` uses `registry`; `filepath`/`os` are used throughout the install flow; `syscall.SysProcAttr{HideWindow: true}` and `exec.Command` are used by several other functions like `launchTray` and the `sc start` call) — confirm this with Step 5's build.

- [ ] **Step 2: Simplify the install-summary messaging**

In `installer/main.go`, replace (currently lines 521, 541-548):

```go
	nativeConsole := ensureWebView2Runtime()

	if err := registerTrayStartup(agentPath); err != nil {
```

with:

```go
	if err := registerTrayStartup(agentPath); err != nil {
```

Then replace (currently lines 541-548):

```go
	if nativeConsole {
		appendStatus("  Native status console: enabled.")
	} else {
		appendStatus("  ⚠ Native status console: NOT available — the tray icon")
		appendStatus("    will open the dashboard in your browser instead of a")
		appendStatus("    native window. Drop the WebView2 runtime installer next")
		appendStatus("    to this installer and re-run it to enable the native console.")
	}
```

with:

```go
	appendStatus("  Status console opens in your default browser from the tray icon.")
```

- [ ] **Step 3: Delete the dead installer test and README**

```bash
git rm installer/webview2_test.go installer/webview2/README.md
```

(If `installer/webview2/` contains anything else after this — e.g. a real, git-ignored `MicrosoftEdgeWebView2RuntimeInstaller.exe` you dropped there — leave the directory and that file in place; `git rm` on the README alone does not touch it.)

- [ ] **Step 4: Remove the WebView2 bundling block from `packaging/windows-build.ps1`**

In `packaging/windows-build.ps1`, replace (currently lines 279-291):

```powershell
# Ship the WebView2 runtime as a sibling file next to the installer, not
# embedded (embedding would balloon the installer from ~14MB to ~190MB).
# Matched by a filename pattern, not an exact name — Microsoft has changed
# this filename before, and a pattern means a future rename doesn't require
# a BAS code change, just re-dropping the renamed file in installer\webview2\.
# See installer\webview2\README.md.
$WebView2Match = Get-ChildItem -Path (Join-Path $InstallerDir "webview2") -Filter "*WebView2*RuntimeInstaller*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($WebView2Match) {
    $wv2MB = [math]::Round($WebView2Match.Length / 1MB)
    Log "  Bundling WebView2 runtime (${wv2MB}MB) as a sibling file - clients without it get the native window automatically"
} else {
    Warn "  WebView2 runtime not found in installer\webview2\ - drop the Evergreen Standalone Installer there to enable auto-install (clients without it use browser fallback)"
}

Push-Location $InstallerDir
```

with:

```powershell
Push-Location $InstallerDir
```

Then replace (currently lines 306-309):

```powershell
if ($WebView2Match) {
    Copy-Item $WebView2Match.FullName -Destination (Join-Path $OutDir $WebView2Match.Name)
    Log "  WebView2 runtime copied alongside installer: $($WebView2Match.Name)"
}

# Also build standalone Windows agent (for manual / side-by-side deploy)
```

with:

```powershell
# Also build standalone Windows agent (for manual / side-by-side deploy)
```

- [ ] **Step 5: Remove the WebView2 bundling logic from `orchestrator/Dockerfile`**

In `orchestrator/Dockerfile`, replace (currently lines 50-68):

```dockerfile
# Ship the WebView2 runtime as a sibling file inside a zip next to
# Audspect_Agent.exe (not go:embed — that would balloon Audspect_Agent.exe
# from ~14MB to ~190MB). Matched by a filename pattern, not an exact name, for the same
# reason as packaging/windows-build.ps1 - see installer/webview2/README.md.
RUN apk add --no-cache zip && \
    cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -H windowsgui" \
    -o /agents/Audspect_Agent.exe . && \
    EXE_MB=$(( $(stat -c%s /agents/Audspect_Agent.exe) / 1024 / 1024 )) && \
    if [ "$EXE_MB" -gt 25 ]; then echo "Audspect_Agent.exe is ${EXE_MB}MB, expected ~14MB - something is being embedded that shouldn't be" >&2; exit 1; fi && \
    WV2=$(find webview2 -maxdepth 1 -iname '*WebView2*RuntimeInstaller*.exe' 2>/dev/null | head -1) && \
    if [ -n "$WV2" ]; then \
        cp "$WV2" /agents/MicrosoftEdgeWebView2RuntimeInstaller.exe && \
        cd /agents && zip -q bas-agent-windows-amd64-setup.zip Audspect_Agent.exe MicrosoftEdgeWebView2RuntimeInstaller.exe && \
        rm Audspect_Agent.exe MicrosoftEdgeWebView2RuntimeInstaller.exe; \
    else \
        cd /agents && zip -q bas-agent-windows-amd64-setup.zip Audspect_Agent.exe && rm Audspect_Agent.exe; \
    fi
```

with:

```dockerfile
RUN apk add --no-cache zip && \
    cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -H windowsgui" \
    -o /agents/Audspect_Agent.exe . && \
    EXE_MB=$(( $(stat -c%s /agents/Audspect_Agent.exe) / 1024 / 1024 )) && \
    if [ "$EXE_MB" -gt 25 ]; then echo "Audspect_Agent.exe is ${EXE_MB}MB, expected ~14MB - something is being embedded that shouldn't be" >&2; exit 1; fi && \
    cd /agents && zip -q bas-agent-windows-amd64-setup.zip Audspect_Agent.exe && rm Audspect_Agent.exe
```

- [ ] **Step 6: Fix the stale flag description in `agent/platform_windows.go`**

In `agent/platform_windows.go`, replace (currently line 49):

```go
	flagStatusWindow = flag.Bool("status-window", false, "Open the WebView2 status console (user session)")
```

with:

```go
	flagStatusWindow = flag.Bool("status-window", false, "Open the status console in the default browser (user session)")
```

- [ ] **Step 7: Fix the stale doc comment in `agent/tray_windows.go`**

In `agent/tray_windows.go`, replace (currently lines 145-146):

```go
// runTray shows the persistent system-tray icon. Left-click / double-click opens
// the WebView2 status console (spawned as a separate --status-window process).
```

with:

```go
// runTray shows the persistent system-tray icon. Left-click / double-click opens
// the status console in the user's default browser (spawned as a separate
// --status-window process).
```

- [ ] **Step 8: Remove the dead host-binding checks in `agent/ui_dashboard.html`**

In `agent/ui_dashboard.html`, replace (currently lines 559-569):

```js
  // Action buttons — bound to native host functions by the tray (WebView2).
  // Fall back to no-op-with-hint if bindings are unavailable.
  $("btnExport").addEventListener("click",function(){
    if(window.basExport){ window.basExport(); flash($("btnExport"),"Exporting…"); }
    else alert("Export is available from the system tray menu.");
  });
  $("btnDashboard").addEventListener("click",function(){
    if(window.basOpenDashboard){ window.basOpenDashboard(lastServerUrl||""); }
    else if(lastServerUrl){ window.open(lastServerUrl,"_blank"); }
    else alert("Server URL not available yet.");
  });
```

with:

```js
  $("btnExport").addEventListener("click",function(){
    alert("Export is available from the system tray menu.");
  });
  $("btnDashboard").addEventListener("click",function(){
    if(lastServerUrl){ window.open(lastServerUrl,"_blank"); }
    else alert("Server URL not available yet.");
  });
```

`flash()` (defined right after this block) becomes unused once the `basExport` branch that called it is gone — leave `flash()`'s definition in place regardless; it's a small generic helper and JS doesn't error on unused functions, so removing it isn't required for correctness. Do not delete it as part of this step — that would be unrelated scope creep beyond what this cleanup needs.

- [ ] **Step 9: Build and test the installer module**

Run:

```bash
cd installer
go build ./...
go vet ./...
go test ./... -v
```

Expected: build succeeds with no unused-import errors, `go vet` is clean, and the existing test suite passes with `TestFindWebView2InstallerIn_*` gone (deleted in Step 3) — no other test in this package referenced those functions, so nothing else should break.

- [ ] **Step 10: Build the agent module and syntax-check the dashboard HTML**

Run:

```bash
cd ../agent
go build ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=amd64 go build ./...
node -e "
  const fs = require('fs');
  const html = fs.readFileSync('ui_dashboard.html', 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  new Function(m[1]);
  console.log('ui_dashboard.html script block parses OK');
"
```

Expected: all three builds succeed (this step's edits are Windows-only files, but the cross-compiles confirm nothing else in the shared package broke), and the dashboard HTML's script block parses.

- [ ] **Step 11: Sanity-check `packaging/windows-build.ps1` and `orchestrator/Dockerfile` changes**

These can't be executed in this environment (PowerShell build script and a Docker build), so verify by inspection instead:

```bash
grep -n -i "webview2" ../packaging/windows-build.ps1 ../orchestrator/Dockerfile
```

Expected: no output — confirms every WebView2 reference is gone from both files. If the grep still finds a match, re-check Steps 4/5 were applied completely.

- [ ] **Step 12: Confirm no WebView2 references remain anywhere in the touched trees**

Run:

```bash
cd ..
grep -rli "webview2" agent/ installer/ packaging/ orchestrator/Dockerfile 2>/dev/null | grep -v "\.exe$"
```

Expected: no output (any `.exe` binary hits are pre-existing build artifacts, not source — excluded on purpose and not part of this cleanup).

- [ ] **Step 13: Commit**

```bash
git add installer/main.go packaging/windows-build.ps1 orchestrator/Dockerfile \
        agent/platform_windows.go agent/tray_windows.go agent/ui_dashboard.html
git commit -m "$(cat <<'EOF'
chore: remove dead WebView2 code, tests, docs, and build steps

The agent's runtime WebView2 hosting was already fully removed
earlier (the tray always opens the status console in the default
browser now, unconditionally -- see statuswindow_windows.go). This
cleans up everything that was left behind: the installer's runtime
bootstrap logic and its now-false "Native status console: enabled /
NOT available" install-summary messaging, the WebView2 sibling-file
bundling in both the PowerShell and Docker build pipelines (~170MB
per Windows build for a feature nothing uses), the dead installer
test/README for that bundling, stale doc comments still describing
the console as WebView2-hosted, and dead dashboard JS checking for
WebView2 host-binding functions that can never exist anymore.

No behavior change -- tray-click-opens-browser works identically.

Note: installer/webview2_test.go and installer/webview2/README.md are
removed via `git rm` in an earlier step of this change, not this
commit's `git add` list (already staged).
EOF
)"
git push
```

---

## Self-Review Notes

- **Spec coverage:** Every item from the approved design has a step: the four installer functions + two consts (Step 1), the install-summary messaging simplification (Step 2), the dead test/README (Step 3), both build pipelines (Steps 4-5), both stale comments (Steps 6-7), and the dead dashboard JS (Step 8). Verification steps (9-12) cover every touched module plus a final repo-wide grep to catch anything missed.
- **Placeholder scan:** No TBD/TODO. Every step shows exact before/after code, not a description of what to change.
- **Type consistency:** N/A — this task only deletes/simplifies existing code and fixes comments; it introduces no new functions, types, or interfaces for a later task to consume, and there is only one task in this plan.
- **Scope check:** Confirmed as a single task — every piece (installer, both build scripts, two agent comments, one HTML file) is part of one cohesive "WebView2 no longer exists, stop pretending it does" change; none of the pieces are independently useful or reviewable in isolation from the others.
