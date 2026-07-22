# WebView2 Sibling-File Packaging — Design Spec

**Goal:** guarantee the agent's status console always opens as a native embedded window (never falls back to a full Microsoft Edge browser tab) on air-gapped/fresh Windows endpoints, **without** bloating `installer.exe` by ~170MB via `go:embed`. Replace the embed-based bundling with a sibling-file approach: ship the Microsoft Edge WebView2 Runtime installer as a separate file next to `installer.exe`, not baked into it.

**Why now:** the agent's status console (`agent/statuswindow_windows.go`) already falls back to opening the dashboard in the default browser when the WebView2 Runtime isn't installed — this was directly observed on a test endpoint (worked one day via WebView2, fell back to a full Edge browser tab the day before, purely because that endpoint didn't yet have the runtime and this repo's installer has no way to provision it — `installer/webview2/` never had the ~170MB runtime file placed in it). The existing `go:embed`-based bundling mechanism (`installer/webview2_bundled.go`, gated by `-tags webview2bundled`) would fix this, but at the cost of turning a ~14MB installer into a ~190MB one — unacceptable for this product's distribution model.

---

## Architecture

### 1. Installer runtime lookup (`installer/main.go`)

Replace the `go:embed`-driven install with a sibling-file lookup, scoped **strictly** to the directory the running `installer.exe` lives in — never Downloads, `%TEMP%`, the current working directory, or `%ProgramData%`. This keeps behavior deterministic and avoids ever executing an unexpected binary from a writable/shared location.

```go
// webView2InstallerGlob matches the Microsoft Edge WebView2 Runtime "Evergreen
// Standalone Installer" filename. A glob (not an exact name) because Microsoft
// has changed this filename before and may again — using a pattern means a
// future rename doesn't require a BAS code change or rebuild, just re-dropping
// the renamed file in the same spot.
const webView2InstallerGlob = "*WebView2*RuntimeInstaller*.exe"

// findWebView2Installer looks for the runtime installer next to the running
// installer.exe — nowhere else. Returns "" if none or more than one match is
// found (ambiguous matches are treated as "not found" rather than guessing).
func findWebView2Installer() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(exePath), webView2InstallerGlob))
	if err != nil || len(matches) != 1 {
		return ""
	}
	return matches[0]
}
```

`ensureWebView2Runtime()` changes from staging+running an embedded byte slice to running the discovered sibling file directly:

```go
func ensureWebView2Runtime() {
	if webView2Installed() {
		appendStatus("[+] WebView2 runtime present.")
		return
	}
	installerPath := findWebView2Installer()
	if installerPath == "" {
		appendStatus("[~] WebView2 runtime missing (no runtime installer found next to this installer) — status console will open in browser.")
		return
	}
	appendStatus("[*] Installing Microsoft Edge WebView2 runtime...")
	cmd := exec.Command(installerPath, "/silent", "/install")
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
```

`webView2Installed()` (the registry-based presence check) is unchanged.

**Delete** `installer/webview2_bundled.go` and `installer/webview2_stub.go` — no build-tag branching is needed anymore since the check is now a plain runtime file-existence glob, not a compile-time embed decision. `installer.exe` is identical regardless of whether the runtime file happens to be sitting next to it.

### 2. Build pipeline 1 — `packaging/windows-build.ps1` (full customer delivery bundle)

This script already stages everything into `dist\bas-install-<version>\` (`$OutDir`) and zips the *entire* folder at the end (`Compress-Archive -Path $OutDir -DestinationPath $ZipPath`), which already generates a `.sha256` checksum sidecar (`$ZipPath.sha256`) — the same checksum convention this spec's "adopt now" list wanted, already present, no new code needed for that part.

Replace the embed-detection block (lines 270-282) with a plain copy — no build tag, no conditional `go build` flag:

```powershell
# Copy the WebView2 runtime installer next to BASAgent-Setup so operators get
# the native status console automatically — see installer/webview2/README.md.
# Matched by a filename pattern (not an exact name): Microsoft has changed
# this filename before, and using a glob means a future rename doesn't
# require a BAS code change, just re-dropping the renamed file here.
$WebView2Match = Get-ChildItem -Path (Join-Path $InstallerDir "webview2") -Filter "*WebView2*RuntimeInstaller*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($WebView2Match) {
    $wv2MB = [math]::Round($WebView2Match.Length / 1MB)
    Log "  Bundling WebView2 runtime (${wv2MB}MB) as a sibling file — clients without it get the native window automatically"
} else {
    Warn "  WebView2 runtime not found in installer\webview2\ - drop the Evergreen Standalone Installer there to enable auto-install (clients without it use browser fallback)"
}
```

```powershell
Push-Location $InstallerDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags="-s -w -H windowsgui" -o "$OutDir\BASAgent-Setup-$Version.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Err "Installer build failed." }
$env:GOOS = ""; $env:GOARCH = ""
Pop-Location
$exeSizeMB = [math]::Round((Get-Item "$OutDir\BASAgent-Setup-$Version.exe").Length / 1MB, 1)
Log "  Installer EXE: BASAgent-Setup-$Version.exe (${exeSizeMB}MB)"
# Size guardrail: this must stay close to its current ~14MB — a jump well
# past that means something got embedded again (e.g. a reverted fix), not a
# one-off size fluctuation worth silently allowing through.
if ($exeSizeMB -gt 25) { Err "BASAgent-Setup-$Version.exe is ${exeSizeMB}MB, expected ~14MB — something is being embedded that shouldn't be (check for -tags webview2bundled or a go:embed regression)." }

if ($WebView2Match) {
    Copy-Item $WebView2Match.FullName -Destination (Join-Path $OutDir $WebView2Match.Name)
    Log "  WebView2 runtime copied alongside installer: $($WebView2Match.Name)"
}
```

No change is needed to the later `Compress-Archive`/checksum step — it already zips the whole `$OutDir`, so the WebView2 file is automatically included in `bas-install-$Version.zip` once it's copied into `$OutDir` above.

### 3. Build pipeline 2 — `orchestrator/Dockerfile` (dashboard's on-demand download)

This is the pipeline that actually matters for `GET /api/agents/download/windows-amd64-setup` — the dashboard's "Download Installer" button. It populates `/agents` inside the `agent-builder` stage (a full `golang:1.26-alpine` image, so `apk add zip` is available), which gets copied verbatim into the final `distroless` runtime image (`COPY --from=agent-builder /agents /agents`) — the orchestrator process serves files straight out of that directory with no shell available at runtime, so the zip must be built during the `agent-builder` stage, not the final stage.

Replace lines 50-57:

```dockerfile
# Bundle the WebView2 runtime as a sibling file next to installer.exe inside a
# zip (not go:embed — that would balloon installer.exe from ~14MB to ~190MB).
# Matched by a filename pattern, not an exact name, for the same reason as
# packaging/windows-build.ps1 - see installer/webview2/README.md.
RUN apk add --no-cache zip && \
    cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -H windowsgui" \
    -o /agents/installer.exe . && \
    EXE_MB=$(( $(stat -c%s /agents/installer.exe) / 1024 / 1024 )) && \
    if [ "$EXE_MB" -gt 25 ]; then echo "installer.exe is ${EXE_MB}MB, expected ~14MB - something is being embedded that shouldn't be" >&2; exit 1; fi && \
    WV2=$(find webview2 -maxdepth 1 -iname '*WebView2*RuntimeInstaller*.exe' 2>/dev/null | head -1) && \
    if [ -n "$WV2" ]; then \
        cp "$WV2" /agents/MicrosoftEdgeWebView2RuntimeInstaller.exe && \
        cd /agents && zip -q bas-agent-windows-amd64-setup.zip installer.exe MicrosoftEdgeWebView2RuntimeInstaller.exe && \
        rm installer.exe MicrosoftEdgeWebView2RuntimeInstaller.exe; \
    else \
        cd /agents && zip -q bas-agent-windows-amd64-setup.zip installer.exe && rm installer.exe; \
    fi
```

`bas-agent-windows-amd64-setup.zip` is the new artifact — always produced, containing just `installer.exe` alone when no runtime file was staged (graceful — matches today's browser-fallback behavior, just zipped), or both files when it was.

### 4. Download registry (`orchestrator/internal/api/handlers.go`)

`agentFiles`'s existing doc comment already describes it correctly: *"the explicit allowlist of downloadable agent artifacts."* This is already the artifact-keyed model — no restructuring needed, just update the one entry that changes:

```go
"windows-amd64-setup": {"bas-agent-windows-amd64-setup.zip", "application/zip"},
```

(was `{"bas-agent-windows-amd64-setup.exe", "application/octet-stream"}`). `DownloadAgent`'s handler body is untouched — it already serves whatever file the map points to from `./agents/`.

**Explicitly out of scope** (no current consumer, would be speculative complexity): online-vs-offline installer variants, MSI packaging. Nothing in this product distinguishes those today; `agentFiles` already scales to them later by adding a map entry when they're real, separately-designed features — no groundwork needed now.

### 5. Frontend (`orchestrator/wwwroot/index.html`)

The "Download Installer" link (line 1627) currently points at the raw `.exe` with `download="BASAgent-Setup.exe"`. Update to reflect the zip:

```html
<a class="btn btn-primary" href="/api/agents/download/windows-amd64-setup" download="BASAgent-Setup.zip" ...>
```

And the caption text below it (line 1632, `BASAgent-Setup.exe · Self-contained GUI wizard · Run as Administrator`) updates to make the two-file/extract-first step explicit: `BASAgent-Setup.zip · Extract, then run installer.exe as Administrator`.

### 6. `installer/webview2/README.md`

Update to describe the sibling-file convention instead of the embed convention: same drop location (`installer/webview2/`), but the filename just needs to match the `*WebView2*RuntimeInstaller*.exe` pattern (the file Microsoft ships today, `MicrosoftEdgeWebView2RuntimeInstaller.exe`, already matches it) — no build tag, no 170MB binary baked into any `.exe`.

---

## Size guardrails (explicit acceptance criterion)

- `bas_agent.exe` / `agent.exe` (the agent binary) — **untouched by this change entirely**. It never imports anything from the `installer` package; nothing here affects its size.
- `installer.exe` / `BASAgent-Setup-$Version.exe` — must stay close to its current size (~14MB as of this spec — `BASAgent-Setup.exe` was 14,653,440 bytes / 13.97MB at the time this was written). Both build pipelines get an explicit size check (`> 25MB` fails the build, generous headroom above ~14MB but two orders of magnitude below the ~190MB embed scenario) so a future regression (e.g. someone reverting to `go:embed`) is caught at build time, not discovered by an operator downloading an unexpectedly huge file.

## Testing

- **Installer unit test** (`installer/*_test.go`, new): `findWebView2Installer()` — no match → `""`; one match → its path; two ambiguous matches → `""` (treated as not-found, not a guess). Use `t.TempDir()` with fixture files, not the real installer directory.
- **`packaging/windows-build.ps1`**: manual verification — run once with no file in `installer/webview2/` (confirms graceful "not found" warning, installer still builds, zip contains only `installer.exe`... run once with a dummy same-sized placeholder file dropped there matching the glob (confirms it gets copied into `$OutDir` and the size guardrail doesn't false-trigger on the *installer* itself, only on an actual embed regression).
- **`orchestrator/Dockerfile`**: build once with and without a staged WebView2 file present in `installer/webview2/` at Docker build-context time, confirm `bas-agent-windows-amd64-setup.zip` is produced correctly in both cases (installer-only vs. installer+runtime) and that `/api/agents/download/windows-amd64-setup` serves it.
- **End-to-end** (manual, on a real Windows endpoint without WebView2 pre-installed): download the zip from the dashboard, extract, run `installer.exe` as Administrator, confirm the WebView2 runtime installs silently and the tray's status console opens as a native window on the very first click — not a browser tab.
