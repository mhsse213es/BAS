# WebView2 Sibling-File Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ship the Microsoft Edge WebView2 Runtime as a separate sibling file next to `installer.exe` (found by a filename pattern, not embedded), so the agent's status console always opens as a native window instead of falling back to a browser tab — without ballooning `installer.exe` from ~14MB to ~190MB.

**Architecture:** `installer/main.go` looks for a file matching `*WebView2*RuntimeInstaller*.exe` next to its own running executable (nowhere else) and runs it directly if found; the `go:embed`-based bundling this replaces is deleted entirely. Both build pipelines (`packaging/windows-build.ps1` for the full customer delivery bundle, `orchestrator/Dockerfile` for the dashboard's on-demand download) copy the runtime file alongside the installer instead of embedding it, with a build-time size guardrail on each so a future regression is caught immediately.

**Tech Stack:** Go (installer, existing conventions), PowerShell, Docker/Alpine shell, vanilla JS/HTML (one frontend link).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-22-webview2-sibling-packaging-design.md` — read it first.
- `installer.exe` must stay close to its current ~14MB (13.97MB / 14,653,440 bytes as of this plan) — both build pipelines fail loudly (`> 25MB`) if it doesn't, rather than silently shipping a bloated installer.
- `bas_agent.exe` (the agent binary) is untouched by this entire plan — it never imports anything from the `installer` package.
- The installer's runtime lookup is scoped **strictly** to its own directory — never Downloads, `%TEMP%`, CWD, or `%ProgramData%`. Ambiguous matches (0 or 2+) are treated as "not found," never a guess.
- The filename match is a **pattern** (`*WebView2*RuntimeInstaller*.exe`), not an exact name, in every place a WebView2 file is looked up — the installer's own runtime lookup and both build pipelines' detection — so a future Microsoft filename change never requires a BAS code change.
- No new "artifact registry" abstraction, no online/offline installer variants, no MSI packaging — `agentFiles` already models artifacts correctly; only its one Windows entry changes.

---

### Task 1: Installer sibling-file lookup

**Files:**
- Modify: `installer/main.go` (`ensureWebView2Runtime`, new `findWebView2Installer` + `webView2InstallerGlob`)
- Delete: `installer/webview2_bundled.go`
- Delete: `installer/webview2_stub.go`
- Modify: `installer/webview2/README.md`
- Test: `installer/webview2_test.go` (new)

**Interfaces:**
- Produces: `findWebView2Installer() string` (empty string = not found/ambiguous), `webView2InstallerGlob` constant — consumed only within this file; no other task depends on these directly (Tasks 2/3 independently reference the same glob pattern in their own PowerShell/shell code, kept in sync by this plan's Global Constraints, not by a shared Go symbol across languages).

- [ ] **Step 1: Write the failing test for `findWebView2Installer`**

Create `installer/webview2_test.go`:
```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withExeAt temporarily overrides os.Executable() by chdir-ing is not
// possible for os.Executable (it reads the real process path), so these
// tests call a small testable seam instead: findWebView2InstallerIn(dir)
// does the glob directly on a given directory, and findWebView2Installer()
// is a one-line wrapper around it using the real executable's directory.
// This keeps the test hermetic (no dependency on where `go test` itself
// happens to run from) without needing to fake os.Executable().
func TestFindWebView2InstallerIn_NoMatch(t *testing.T) {
	dir := t.TempDir()
	if got := findWebView2InstallerIn(dir); got != "" {
		t.Fatalf("no files present: got %q, want empty", got)
	}
}

func TestFindWebView2InstallerIn_OneMatch(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "MicrosoftEdgeWebView2RuntimeInstaller.exe")
	if err := os.WriteFile(want, []byte("stub"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// A non-matching file in the same directory must not interfere.
	if err := os.WriteFile(filepath.Join(dir, "installer.exe"), []byte("stub"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if got := findWebView2InstallerIn(dir); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFindWebView2InstallerIn_RenamedFileStillMatches(t *testing.T) {
	// Confirms the pattern match (not an exact name) — a future Microsoft
	// filename change would still be found here without a code change.
	dir := t.TempDir()
	want := filepath.Join(dir, "EdgeWebView2Setup-RuntimeInstaller-v2.exe")
	if err := os.WriteFile(want, []byte("stub"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if got := findWebView2InstallerIn(dir); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFindWebView2InstallerIn_AmbiguousMatchesReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"MicrosoftEdgeWebView2RuntimeInstaller.exe", "OldWebView2RuntimeInstaller.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stub"), 0644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
	}
	if got := findWebView2InstallerIn(dir); got != "" {
		t.Fatalf("two matches: got %q, want empty (ambiguous match must not guess)", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd installer && go test ./... -run TestFindWebView2InstallerIn -v`
Expected: FAIL — `undefined: findWebView2InstallerIn`.

- [ ] **Step 3: Implement `findWebView2Installer`/`findWebView2InstallerIn` and rewrite `ensureWebView2Runtime`**

In `installer/main.go`, find:
```go
func ensureWebView2Runtime() {
	if webView2Installed() {
		appendStatus("[+] WebView2 runtime present.")
		return
	}
	if len(webview2RuntimeInstaller) == 0 {
		appendStatus("[~] WebView2 runtime missing and not bundled — status console will open in browser.")
		return
	}
	appendStatus("[*] Installing Microsoft Edge WebView2 runtime...")
	tmp := filepath.Join(os.TempDir(), "MicrosoftEdgeWebView2RuntimeInstaller.exe")
	if err := os.WriteFile(tmp, webview2RuntimeInstaller, 0755); err != nil {
		appendStatus("[~] Could not stage WebView2 installer: " + err.Error())
		return
	}
	defer os.Remove(tmp)
	cmd := exec.Command(tmp, "/silent", "/install")
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
Replace with:
```go
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

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd installer && go test ./... -run TestFindWebView2InstallerIn -v`
Expected: all 4 PASS.

- [ ] **Step 5: Delete the now-unused embed machinery**

```bash
git rm installer/webview2_bundled.go installer/webview2_stub.go
```

- [ ] **Step 6: Verify the installer package still builds without the deleted files**

Run: `cd installer && go build ./...`
Expected: no errors. (`webview2RuntimeInstaller` is no longer referenced anywhere in `main.go` after Step 3 — confirm with `grep -n webview2RuntimeInstaller installer/main.go`, expected: no output.)

- [ ] **Step 7: Update the README**

In `installer/webview2/README.md`, find:
```markdown
## How it is used

- When the file is present, `packaging/windows-build.ps1` and the Docker build
  detect it and compile the installer with `-tags webview2bundled`, embedding it
  (see `installer/webview2_bundled.go`).
- At install time, the GUI installer checks the WebView2 registry key and, if
  the runtime is missing, runs the embedded installer with `/silent /install`
  before launching the tray (see `ensureWebView2Runtime` in `main.go`).
- A bare `go build` (no tag) ignores the file and keeps the browser fallback
  (see `installer/webview2_stub.go`), so the binary is optional for dev builds.
```
Replace with:
```markdown
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
```

- [ ] **Step 8: Commit**

```bash
git add installer/main.go installer/webview2_test.go installer/webview2/README.md
git commit -m "feat(installer): find WebView2 runtime as a sibling file instead of embedding it"
git push
```

---

### Task 2: Windows-native build pipeline (`packaging/windows-build.ps1`)

**Files:**
- Modify: `packaging/windows-build.ps1`

**Interfaces:**
- Consumes: nothing from Task 1 (PowerShell, separate from the Go installer's own runtime lookup — kept in sync by convention, per Global Constraints, not a shared symbol).
- Produces: `$OutDir\BASAgent-Setup-$Version.exe` (unchanged filename) + the matched WebView2 file copied alongside it in `$OutDir`, both automatically swept into the existing `bas-install-$Version.zip` by the script's pre-existing end-of-run `Compress-Archive` step (no change needed there).

- [ ] **Step 1: Replace the embed-detection block with a plain copy + size guardrail**

In `packaging/windows-build.ps1`, find:
```powershell
# Bundle the WebView2 runtime if the Evergreen Standalone Installer was placed
# at installer\webview2\. When present, the installer silently installs it on
# clients that lack the runtime so the status console opens natively (not the
# browser). Absent -> graceful browser fallback (see installer\webview2\README.md).
$WebView2Installer = Join-Path $InstallerDir "webview2\MicrosoftEdgeWebView2RuntimeInstaller.exe"
$installerTags = @()
if (Test-Path $WebView2Installer) {
    $wv2MB = [math]::Round((Get-Item $WebView2Installer).Length / 1MB)
    Log "  Bundling WebView2 runtime (${wv2MB}MB) - clients without it get the native window automatically"
    $installerTags = @("-tags", "webview2bundled")
} else {
    Warn "  WebView2 runtime not bundled - drop MicrosoftEdgeWebView2RuntimeInstaller.exe in installer\webview2\ to enable auto-install (clients without it use browser fallback)"
}

Push-Location $InstallerDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build @installerTags -ldflags="-s -w -H windowsgui" -o "$OutDir\BASAgent-Setup-$Version.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Err "Installer build failed." }
$env:GOOS = ""; $env:GOARCH = ""
Pop-Location
$exeSizeMB = [math]::Round((Get-Item "$OutDir\BASAgent-Setup-$Version.exe").Length / 1MB, 1)
Log "  Installer EXE: BASAgent-Setup-$Version.exe (${exeSizeMB}MB)"
```
Replace with:
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
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags="-s -w -H windowsgui" -o "$OutDir\BASAgent-Setup-$Version.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Err "Installer build failed." }
$env:GOOS = ""; $env:GOARCH = ""
Pop-Location
$exeSizeMB = [math]::Round((Get-Item "$OutDir\BASAgent-Setup-$Version.exe").Length / 1MB, 1)
Log "  Installer EXE: BASAgent-Setup-$Version.exe (${exeSizeMB}MB)"
# Size guardrail: this must stay close to its current ~14MB. A jump well past
# that means something is being embedded again (e.g. a reverted fix), not a
# one-off fluctuation worth silently allowing through.
if ($exeSizeMB -gt 25) { Err "BASAgent-Setup-$Version.exe is ${exeSizeMB}MB, expected ~14MB - something is being embedded that shouldn't be (check for a go:embed regression)." }

if ($WebView2Match) {
    Copy-Item $WebView2Match.FullName -Destination (Join-Path $OutDir $WebView2Match.Name)
    Log "  WebView2 runtime copied alongside installer: $($WebView2Match.Name)"
}
```

- [ ] **Step 2: Verify the script's PowerShell syntax is valid**

Run: `powershell -NoProfile -Command "$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw 'packaging\windows-build.ps1'), [ref]$null); Write-Host 'PARSE_OK'"`
Expected: `PARSE_OK` with no parser errors printed.

- [ ] **Step 3: Manual dry-run verification (requires Docker Desktop running — this script builds the orchestrator Docker image as part of its normal flow)**

Run with no WebView2 file staged (confirms graceful skip path):
```powershell
Remove-Item -ErrorAction SilentlyContinue installer\webview2\*.exe
.\packaging\windows-build.ps1 -Version 0.0.0-test -SkipBuild
```
Expected in the log output: `WebView2 runtime not found in installer\webview2\ ...` warning, `Installer EXE: BASAgent-Setup-0.0.0-test.exe (~14MB)`, and the run completes successfully (no `Err` abort).

Then stage a placeholder file matching the glob and re-run to confirm it's picked up and copied:
```powershell
"stub" | Out-File installer\webview2\MicrosoftEdgeWebView2RuntimeInstaller.exe
.\packaging\windows-build.ps1 -Version 0.0.0-test -SkipBuild
Test-Path "dist\bas-install-0.0.0-test\MicrosoftEdgeWebView2RuntimeInstaller.exe"
Remove-Item installer\webview2\MicrosoftEdgeWebView2RuntimeInstaller.exe
```
Expected: `Bundling WebView2 runtime (0MB) as a sibling file ...` logged, the `Test-Path` check returns `True`, and `BASAgent-Setup-0.0.0-test.exe`'s size is still ~14MB (the guardrail must not false-trigger on the *installer* itself — only an actual embed regression should trip it).

- [ ] **Step 4: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "feat(packaging): ship WebView2 runtime as a sibling file, not embedded"
git push
```

---

### Task 3: Docker pipeline, download registry, and frontend link

**Files:**
- Modify: `orchestrator/Dockerfile`
- Modify: `orchestrator/internal/api/handlers.go:552` (`agentFiles` entry)
- Modify: `orchestrator/wwwroot/index.html:1627-1632`
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (hardlinked twin)

**Interfaces:**
- Consumes: nothing from Tasks 1/2 directly (separate build pipeline, kept in sync by the Global Constraints convention).
- Produces: `bas-agent-windows-amd64-setup.zip` in `/agents` (served by the pre-existing `DownloadAgent` handler, no handler code changes needed — only the `agentFiles` map entry it reads from).

- [ ] **Step 1: Replace the Dockerfile's embed-tag block with a zip-producing block + size guardrail**

In `orchestrator/Dockerfile`, find:
```dockerfile
# Bundle the WebView2 runtime into the installer when the Evergreen Standalone
# Installer is present at installer/webview2/ (auto-installed on clients lacking
# the runtime so the status console opens natively). Absent -> browser fallback.
RUN cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    TAGS=""; if [ -f webview2/MicrosoftEdgeWebView2RuntimeInstaller.exe ]; then TAGS="webview2bundled"; fi && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -tags "$TAGS" -ldflags="-s -w -H windowsgui" \
    -o /agents/bas-agent-windows-amd64-setup.exe .
```
Replace with:
```dockerfile
# Ship the WebView2 runtime as a sibling file inside a zip next to
# installer.exe (not go:embed — that would balloon installer.exe from ~14MB
# to ~190MB). Matched by a filename pattern, not an exact name, for the same
# reason as packaging/windows-build.ps1 - see installer/webview2/README.md.
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

- [ ] **Step 2: Update the download registry**

In `orchestrator/internal/api/handlers.go`, find:
```go
	"windows-amd64-setup": {"bas-agent-windows-amd64-setup.exe", "application/octet-stream"},
```
Replace with:
```go
	"windows-amd64-setup": {"bas-agent-windows-amd64-setup.zip", "application/zip"},
```

- [ ] **Step 3: Update the frontend download link**

In `orchestrator/wwwroot/index.html`, find:
```html
            <a class="btn btn-primary" href="/api/agents/download/windows-amd64-setup" download="BASAgent-Setup.exe"
               style="display:inline-flex;align-items:center;gap:0.4rem;padding:0.55rem 1.1rem;font-size:0.85rem;font-weight:600">
              <svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M7.47 10.78a.75.75 0 0 0 1.06 0l3.75-3.75a.75.75 0 0 0-1.06-1.06L8.75 8.44V1.75a.75.75 0 0 0-1.5 0v6.69L4.78 5.97a.75.75 0 0 0-1.06 1.06l3.75 3.75ZM3.75 13a.75.75 0 0 0 0 1.5h8.5a.75.75 0 0 0 0-1.5h-8.5Z"/></svg>
              Download Installer
            </a>
            <div style="font-size:0.75rem;color:var(--muted)">BASAgent-Setup.exe &nbsp;·&nbsp; Self-contained GUI wizard &nbsp;·&nbsp; Run as Administrator</div>
```
Replace with:
```html
            <a class="btn btn-primary" href="/api/agents/download/windows-amd64-setup" download="BASAgent-Setup.zip"
               style="display:inline-flex;align-items:center;gap:0.4rem;padding:0.55rem 1.1rem;font-size:0.85rem;font-weight:600">
              <svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M7.47 10.78a.75.75 0 0 0 1.06 0l3.75-3.75a.75.75 0 0 0-1.06-1.06L8.75 8.44V1.75a.75.75 0 0 0-1.5 0v6.69L4.78 5.97a.75.75 0 0 0-1.06 1.06l3.75 3.75ZM3.75 13a.75.75 0 0 0 0 1.5h8.5a.75.75 0 0 0 0-1.5h-8.5Z"/></svg>
              Download Installer
            </a>
            <div style="font-size:0.75rem;color:var(--muted)">BASAgent-Setup.zip &nbsp;·&nbsp; Extract, then run installer.exe as Administrator</div>
```

- [ ] **Step 4: Verify the hardlink twin is in sync**

```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output.

- [ ] **Step 5: Structural verification**

```bash
grep -n "bas-agent-windows-amd64-setup.zip" orchestrator/internal/api/handlers.go
grep -n "BASAgent-Setup.zip" orchestrator/wwwroot/index.html
```
Expected: one match each.

- [ ] **Step 6: Update the Go test fixture for the changed download entry, if one exists**

Run: `grep -rn "bas-agent-windows-amd64-setup.exe\|windows-amd64-setup" orchestrator/internal/api/*_test.go`
If any test asserts on the old `.exe` filename or `application/octet-stream` MIME type for the `windows-amd64-setup` platform key specifically, update it to expect `bas-agent-windows-amd64-setup.zip` / `application/zip` instead. If no test references this specific entry, no change needed here.

- [ ] **Step 7: Docker build verification (requires Docker Desktop running)**

```bash
docker build -f orchestrator/Dockerfile -t bas-orchestrator-webview2-verify --target agent-builder .
docker run --rm bas-orchestrator-webview2-verify sh -c "ls -la /agents/bas-agent-windows-amd64-setup.zip && unzip -l /agents/bas-agent-windows-amd64-setup.zip"
docker rmi bas-orchestrator-webview2-verify
```
Expected: the zip exists, `unzip -l` lists at least `installer.exe` (and `MicrosoftEdgeWebView2RuntimeInstaller.exe` too if a matching file was present in `installer/webview2/` at build time — absent otherwise, matching the graceful-fallback behavior).

- [ ] **Step 8: Run the orchestrator test suite**

Run: `cd orchestrator && go test ./internal/api/... -count=1 2>&1 | tail -20`
Expected: `ok`, no failures.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/Dockerfile orchestrator/internal/api/handlers.go orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(orchestrator): serve the Windows installer as a zip with the WebView2 runtime alongside it"
git push
```

---

## Self-Review Notes

**Spec coverage:** Task 1 covers the spec's "Installer runtime lookup" section in full (glob-based lookup, directory-scoped, ambiguous-match handling, deletion of the embed machinery, README update). Task 2 covers "Build pipeline 1" in full (copy instead of embed, size guardrail, automatic inclusion in the existing delivery zip — verified no new zip-step code was needed there since `Compress-Archive` already zips the whole `$OutDir`). Task 3 covers "Build pipeline 2," "Download registry," and "Frontend" in full (Docker-stage zip creation with `apk add zip`, exact-byte size guardrail via `stat -c%s` rather than block-rounded `du`, the one `agentFiles` entry change, the one frontend link/caption change). The spec's "explicitly out of scope" items (online/offline variants, MSI, a new artifact-registry abstraction) are correctly not built anywhere in this plan.

**Placeholder scan:** none — every step has complete code, or an exact command with a precisely described expected result (including the two-run before/after dry-run in Task 2 Step 3, which is as close to a real "test" as a PowerShell packaging script gets without a full CI harness).

**Type consistency:** `findWebView2Installer()`/`findWebView2InstallerIn(dir string) string` (Task 1) match exactly between the implementation and the test file signatures. `webView2InstallerGlob = "*WebView2*RuntimeInstaller*.exe"` (Task 1, Go) is the same literal pattern used in Task 2's PowerShell (`-Filter "*WebView2*RuntimeInstaller*.exe"`) and Task 3's shell (`-iname '*WebView2*RuntimeInstaller*.exe'`) — three independent implementations of the same convention (unavoidable, since they're three different languages/pipelines with no shared runtime), each documented as such in its own comment so a future edit to one is a visible prompt to check the other two. `agentFiles["windows-amd64-setup"]`'s new filename (`bas-agent-windows-amd64-setup.zip`, Task 3 Step 2) matches exactly what Task 3 Step 1's Dockerfile `zip` command produces.
