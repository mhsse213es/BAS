# BAS Platform -- Windows Build & Delivery Packager
#
# Builds the Docker image, packages all client delivery files, and generates
# a customer license -- all from Windows with Docker Desktop.
#
# Usage:
#   .\packaging\windows-build.ps1 `
#       -Version    1.6.0 `
#       -Customer   "HDFC Bank" `
#       -CustomerID "hdfc-prod-001" `
#       -Days       365
#
# Output:
#   dist\bas-install-<version>\         delivery folder
#   dist\bas-install-<version>.zip      zip to send to client
#   <customer-id>.lic                   license to send to client
#
# Prerequisites: Docker Desktop running, Go installed (for licensegen)

param(
    [string] $Version    = "1.6.0",
    [string] $Customer   = "",
    [string] $CustomerID = "",
    [int]    $Days       = 365,
    [switch] $SkipBuild,         # pass -SkipBuild to repackage without rebuilding image

    # -- D1 release signing (docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md) --
    # Credentials are always parameters/env vars, never hardcoded. A customer
    # build (-Customer/-CustomerID both set) defaults every *Required flag to
    # $true -- a production release must not silently ship unsigned. A bare
    # dev build (no -Customer) defaults them to $false, unchanged from today's
    # behavior, so the existing local dev/test loop isn't broken by this task.
    [string] $WindowsCertThumbprint = $env:BAS_WINDOWS_CERT_THUMBPRINT,
    [Nullable[bool]] $WindowsSigningRequired = $null,
    [Nullable[bool]] $GpgSigningRequired     = $null
)

$IsCustomerBuild = ($Customer -ne "" -and $CustomerID -ne "")
if ($null -eq $WindowsSigningRequired) { $WindowsSigningRequired = $IsCustomerBuild }
if ($null -eq $GpgSigningRequired)     { $GpgSigningRequired     = $IsCustomerBuild }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# A previous invocation of this script that failed mid-run (e.g. inside the
# legacy-agent build section below) can leave GOTOOLCHAIN/GOWORK/GOOS/GOARCH/
# CGO_ENABLED set in this PowerShell session, since $ErrorActionPreference =
# "Stop" aborts the script before its own env-var reset lines run. Clear them
# unconditionally at the start so a fresh invocation never inherits a
# poisoned environment from an earlier failed one in the same window.
$env:GOTOOLCHAIN = ""; $env:GOWORK = ""; $env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""

$RepoRoot  = Split-Path -Parent $PSScriptRoot
$DistDir   = Join-Path $RepoRoot "dist"
$OutName   = "bas-install-$Version"
$OutDir    = Join-Path $DistDir $OutName
$ZipPath   = Join-Path $DistDir "$OutName.zip"

function Log  { param($msg) Write-Host "[+] $msg" -ForegroundColor Green  }
function Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Err  { param($msg) Write-Host "[x] $msg" -ForegroundColor Red; exit 1 }

# ConvertToLF rewrites a file with Unix (LF) line endings, no BOM. The build
# host may check shell/config files out as CRLF (core.autocrlf); these run on
# the client's Linux box, where a CRLF is fatal (bash reads `set -o pipefail\r`
# and rejects `pipefail\r`). Normalize on copy so the bundle is always LF
# regardless of the host's git settings.
function ConvertToLF {
    param($path)
    if (Test-Path $path) {
        # ReadAllText with explicit UTF-8 preserves box-drawing/arrow chars in the
        # template; Get-Content defaults to the system code page (Windows-1252) and
        # corrupts multi-byte sequences into mojibake (â€" â† â•).
        $utf8 = [System.Text.UTF8Encoding]::new($false) # no BOM
        $t = [System.IO.File]::ReadAllText($path, $utf8) -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText($path, $t, $utf8)
    }
}

# -- 0. Verify prerequisites --------------------------------------------------
Log "Verifying prerequisites..."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Err "Docker not found. Install Docker Desktop: https://docs.docker.com/desktop/windows/"
}
try { docker info 2>$null | Out-Null } catch { Err "Docker daemon not running. Start Docker Desktop." }
Log "  Docker OK"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Err "Go not found. Install from https://go.dev/dl/"
}
Log "  Go OK: $(go version)"

# -- 0b. Content signing: scenarios + manifest + wwwroot hash -----------------
# Must run BEFORE docker build so signed artifacts travel into the image via
# the COPY context. The private key never leaves this host  -  only the public
# key (compiled into the binary) is distributed to clients.
#
# Key lifecycle:
#   First run: generates RSA-4096 private_key.pem in orchestrator\ and injects
#              the matching public key into orchestrator\internal\integrity\signing.go
#   Subsequent runs: re-uses existing key (skips keygen)
#   CRITICAL: back up orchestrator\private_key.pem  -  losing it means scenarios
#             can never be validly re-signed.

$OrchestratorDir = Join-Path $RepoRoot "orchestrator"
$PrivKeyPath     = Join-Path $OrchestratorDir "private_key.pem"
$ScenariosDir    = Join-Path $RepoRoot "scenarios"

Log "Content signing pre-build..."

# 0b-i. RSA keypair  -  idempotent: only runs once per install.
if (-not (Test-Path $PrivKeyPath)) {
    Log "  No private_key.pem found. Generating RSA-4096 keypair..."
    Push-Location $OrchestratorDir
    go run scripts/signer.go keygen
    $kgExit = $LASTEXITCODE
    Pop-Location
    if ($kgExit -ne 0) { Err "RSA keygen failed  -  check Go is installed and orchestrator/scripts/signer.go exists." }
    Log "  Keypair generated. BACK UP $PrivKeyPath before deleting or reformatting this machine."
} else {
    Log "  Found existing private_key.pem"
}

# 0b-ii. Sign every scenario YAML (re-signs on each build to capture any edits).
#         .sig files are created alongside each .yaml and travel into the Docker
#         image via 'COPY scenarios /scenarios'.
if (Test-Path $ScenariosDir) {
    $yamls = Get-ChildItem -Path $ScenariosDir -Filter "*.yaml" -Recurse -File
    Log "  Signing $($yamls.Count) scenario YAML(s)..."
    foreach ($yaml in $yamls) {
        Push-Location $OrchestratorDir
        go run scripts/signer.go sign private_key.pem $yaml.FullName
        $signExit = $LASTEXITCODE
        Pop-Location
        if ($signExit -ne 0) { Err "Failed to sign scenario: $($yaml.Name)" }
    }
    Log "  All scenarios signed."
} else {
    Warn "  No scenarios\ directory found at repo root  -  skipping scenario signing."
}

# 0b-iii. Sign BINARIES.sha256 manifest - file is extracted from the Docker
# image in step 5c (after the build), then signed there. Signing confirmed below.
Log "  BINARIES.sha256: will be extracted from image and signed in step 5c."

# 0b-iv. SHA-256 hash of wwwroot/index.html, injected into the binary via
#        --build-arg BAS_WWWROOT_HASH so StaticHandler() halts on mismatch.
$WWWRootHash = ""
$IndexHtmlPath = Join-Path $OrchestratorDir "wwwroot\index.html"
if (Test-Path $IndexHtmlPath) {
    $WWWRootHash = (Get-FileHash -Path $IndexHtmlPath -Algorithm SHA256).Hash.ToLower()
    Log "  wwwroot/index.html hash: $($WWWRootHash.Substring(0,16))..."
} else {
    Warn "  wwwroot/index.html not found  -  UI tamper-detection will be DISABLED in this build."
}

# -- 1. Build Docker image ----------------------------------------------------
$OrchestratorTag = "bas-orchestrator:$Version"

if (-not $SkipBuild) {
    # Obfuscation (garble -literals -tiny, scoped to our module via GOGARBLE) runs
    # inside orchestrator/Dockerfile  -  see that file for the GOGARBLE rationale.
    # BAS_WWWROOT_HASH is injected via -X ldflags so StaticHandler() verifies the
    # dashboard SPA hash at startup. BAS_SIGNING_KEY is not needed  -  the public key
    # was already compiled into signing.go by step 0b-i above.
    Log "Building $OrchestratorTag (garble -literals -tiny - this takes 5-10 min)..."
    $buildExtraArgs = @("--build-arg", "BAS_VERSION=$Version")
    if ($WWWRootHash -ne "") {
        $buildExtraArgs += @("--build-arg", "BAS_WWWROOT_HASH=$WWWRootHash")
    }
    # docker build (BuildKit) writes routine progress to stderr; with
    # $ErrorActionPreference='Stop' (set above) PowerShell turns that into a
    # terminating NativeCommandError before the build even finishes, well
    # before the $LASTEXITCODE check below ever runs -- same class of issue
    # the GPG section below already works around. Pre-existing, unrelated to
    # D1; found only because Task 5's end-to-end verification needs this
    # step to actually complete.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        docker build -t $OrchestratorTag @buildExtraArgs -f "$RepoRoot\orchestrator\Dockerfile" $RepoRoot
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    if ($LASTEXITCODE -ne 0) { Err "Docker build failed." }
    Log "Image built: $OrchestratorTag"
} else {
    Warn "Skipping image build (-SkipBuild). Using existing $OrchestratorTag."
    if ($WWWRootHash -eq "") { Warn "  (UI tamper hash was not computed  -  existing image retains its compiled hash)" }
}

# -- 2. Pull dependency images ------------------------------------------------
Log "Pulling postgres:16-alpine..."
docker pull postgres:16-alpine
if ($LASTEXITCODE -ne 0) { Err "Failed to pull postgres:16-alpine." }

Log "Pulling ghcr.io/mitre/caldera:latest..."
docker pull ghcr.io/mitre/caldera:latest
if ($LASTEXITCODE -ne 0) { Warn "Failed to pull Caldera image - bundle will exclude it." }

Log "Pulling chromedp/headless-shell:latest (HTML->PDF report renderer)..."
docker pull chromedp/headless-shell:latest
if ($LASTEXITCODE -ne 0) { Warn "Failed to pull headless-shell - PDF reports will fall back to the built-in renderer." }

# Build the custom Caldera image with the adversary-emulation library baked in.
# This is the only place the emulation library is cloned (build host has internet).
Log "Building bas-caldera:$Version (emu library)..."
# Same stderr/$ErrorActionPreference issue as the orchestrator docker build
# above -- without this, a failure here doesn't even reach the graceful
# Warn-and-continue below; the whole script aborts instead.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    docker build -t "bas-caldera:$Version" "$RepoRoot\packaging\caldera"
} finally {
    $ErrorActionPreference = $prevEAP
}
if ($LASTEXITCODE -ne 0) { Warn "Failed to build bas-caldera image - bundle will fall back to stock Caldera." }

# -- 3. Create output directory structure -------------------------------------
Log "Staging delivery package: $OutDir"
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force -Path "$OutDir\images" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutDir\systemd" | Out-Null

# -- 4. Save Docker images (.tar -- docker load accepts both .tar and .tar.gz) -
Log "Saving Docker images (this may take a few minutes)..."

Log "  Saving postgres:16-alpine..."
docker save postgres:16-alpine -o "$OutDir\images\postgres-16-alpine.tar"
if ($LASTEXITCODE -ne 0) { Err "Failed to save postgres:16-alpine image." }
Log "  Saved: postgres-16-alpine.tar"

$chromeExists = docker image inspect "chromedp/headless-shell:latest" 2>$null
if ($chromeExists) {
    Log "  Saving chromedp/headless-shell:latest..."
    docker save chromedp/headless-shell:latest -o "$OutDir\images\headless-shell.tar"
    $csMB = [math]::Round((Get-Item "$OutDir\images\headless-shell.tar").Length / 1MB)
    Log "  Saved: headless-shell.tar (${csMB}MB)"
} else {
    Warn "  headless-shell image not present - PDF reports will use the built-in fallback renderer."
}

$basCalderaExists = docker image inspect "bas-caldera:$Version" 2>$null
if ($basCalderaExists) {
    Log "  Saving bas-caldera:$Version..."
    docker save "bas-caldera:$Version" -o "$OutDir\images\bas-caldera-$Version.tar"
    Log "  Saved: bas-caldera-$Version.tar"
} else {
    $calderaExists = docker image inspect "ghcr.io/mitre/caldera:latest" 2>$null
    if ($calderaExists) {
        Log "  Saving fallback ghcr.io/mitre/caldera:latest..."
        docker save ghcr.io/mitre/caldera:latest -o "$OutDir\images\caldera-latest.tar"
        Log "  Saved: caldera-latest.tar"
    } else {
        Warn "No Caldera image available - skipping."
    }
}

. "$RepoRoot\packaging\signing\sign-windows.ps1"

# -- 5a. Build Windows agent binary + installer EXE ---------------------------
Log "Building Windows agent binary..."
$AgentDir     = Join-Path $RepoRoot "agent"
$InstallerDir = Join-Path $RepoRoot "installer"

# Embed requireAdministrator manifest into the binary via rsrc.
# rsrc generates rsrc.syso which go build picks up automatically,
# so the OS handles UAC elevation before the process starts (no
# double-process dance where the first window closes instantly).
Log "  Embedding UAC manifest (requireAdministrator)..."
$GoPathBin = Join-Path (go env GOPATH) "bin"
$rsrcBin   = Join-Path $GoPathBin "rsrc.exe"
if (-not (Test-Path $rsrcBin)) {
    go install github.com/akavel/rsrc@latest
    if ($LASTEXITCODE -ne 0) { Warn "    rsrc install failed - agent will rely on runtime self-elevation" }
}
if (Test-Path $rsrcBin) {
    Push-Location $AgentDir
    & $rsrcBin -manifest bas_agent.exe.manifest -ico logo.ico -arch amd64 -o rsrc.syso
    $rsrcExit = $LASTEXITCODE
    Pop-Location
    if ($rsrcExit -eq 0) { Log "    rsrc.syso generated - manifest + icon embedded" }
    else { Warn "    rsrc failed - manifest + icon will not be embedded" }
} else {
    Warn "    rsrc not available - agent will runtime-elevate via ShellExecuteW"
}

Push-Location $AgentDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
# -H windowsgui: without this the agent is a console-subsystem binary, and
# Windows auto-allocates a visible console for it whenever something launches
# it without an inherited console (e.g. the tray's Run-key entry firing at
# logon) -- that console shows raw log output and, since the tray icon lives
# in the same process, closing it kills the tray too. platformPreStart's
# ensureConsole()/AllocConsole() already exists specifically to open a
# console on demand for genuine interactive use (--install/--uninstall/plain
# console mode); this flag just lets that mechanism do its job everywhere
# instead of the OS pre-empting it.
#
# C4: delete any pre-existing output first. `go build -o` skips rewriting
# the destination when it decides the new binary is unchanged from what's
# already there (a build-cache optimization to avoid bumping mtimes) --
# verified empirically to leave a PREVIOUSLY SIGNED bas_agent.exe from an
# earlier build completely untouched, cert and all, even though this run
# goes on to log "will not be signed". Without this delete, the signed/
# unsigned state of the embed source would depend on workspace history
# instead of this run's own cert/thumbprint -- exactly the non-determinism
# C4 exists to eliminate.
if (Test-Path "$InstallerDir\bas_agent.exe") { Remove-Item -Force "$InstallerDir\bas_agent.exe" }
go build -ldflags="-s -w -H windowsgui" -o "$InstallerDir\bas_agent.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Err "Agent build failed." }
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Pop-Location
Log "  Agent binary built: installer\bas_agent.exe"

# C4: sign the agent binary HERE, before the installer embeds it via
# go:embed, so the installer's embedded copy and the standalone artifact
# built further below are the exact same signed bytes -- not two
# independent builds that happen to both get signed later. Mirrors the
# Dockerfile's own build-once-then-cp pattern (orchestrator/Dockerfile:
# 34,47), which never had this problem because it only ever builds the
# agent once.
if ($WindowsCertThumbprint) {
    $agentSigned = Invoke-AuthenticodeSigning -Path "$InstallerDir\bas_agent.exe" -CertThumbprint $WindowsCertThumbprint
    if (-not $agentSigned -and $WindowsSigningRequired) {
        Err "Authenticode signing failed for installer\bas_agent.exe and Windows signing is required for this build."
    } elseif (-not $agentSigned) {
        Warn "Authenticode signing failed for installer\bas_agent.exe (not required for this build -- continuing)."
    } else {
        Log "  installer\bas_agent.exe signed (embedded by the installer build below)."
    }
} elseif ($WindowsSigningRequired) {
    Err "Windows signing is required for this build (customer build) but -WindowsCertThumbprint / BAS_WINDOWS_CERT_THUMBPRINT is not set."
} else {
    Warn "No Windows signing certificate configured -- installer\bas_agent.exe will not be signed (dev build, not required)."
}

Log "Building installer EXE (embeds the single agent binary)..."
Log "  Embedding UAC manifest into installer..."
if (Test-Path $rsrcBin) {
    Push-Location $InstallerDir
    & $rsrcBin -manifest installer.exe.manifest -ico logo.ico -arch amd64 -o rsrc.syso
    $rsrcInstExit = $LASTEXITCODE
    Pop-Location
    if ($rsrcInstExit -eq 0) { Log "    rsrc.syso generated - installer manifest + icon embedded" }
    else { Warn "    rsrc failed for installer - manifest + icon will not be embedded" }
} else {
    Warn "    rsrc not available - installer will use runtime self-elevation"
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

# Also stage the standalone Windows agent artifact (for manual / side-by-side
# deploy). Copied from the already-signed installer\bas_agent.exe, not
# rebuilt -- see the C4 comment above. A second independent build here
# would silently reintroduce the exact mismatch this fix removes (even
# with identical source and flags, re-signing a second time would embed a
# different RFC 3161 timestamp token and the two files would diverge).
Log "Staging standalone Windows agent binary..."
Copy-Item "$InstallerDir\bas_agent.exe" "$OutDir\bas-agent-windows-amd64.exe" -Force
if (-not (Test-Path "$OutDir\bas-agent-windows-amd64.exe")) {
    Warn "Standalone Windows agent staging failed."
} else {
    $wSizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-amd64.exe (${wSizeMB}MB)"

    # C4's core invariant: the embed source and the standalone copy must be
    # byte-identical. Unconditional (not gated by $WindowsSigningRequired) --
    # this is a build-construction fact, not a signing policy, and under
    # this design it cannot legitimately fail.
    $embedHash = (Get-FileHash -Path "$InstallerDir\bas_agent.exe" -Algorithm SHA256).Hash
    $standaloneHash = (Get-FileHash -Path "$OutDir\bas-agent-windows-amd64.exe" -Algorithm SHA256).Hash
    if ($embedHash -ne $standaloneHash) {
        Err "installer\bas_agent.exe and bas-agent-windows-amd64.exe diverged after a copy -- this should be structurally impossible; investigate before shipping."
    }
}

# -- 5a2. Build Legacy Windows agent binary (amd64 only) ---------------------
# Separately toolchained via GOTOOLCHAIN=go1.20.14 (agent-legacy/go.mod stays
# at a bare `go 1.20` -- the `toolchain` directive predates Go 1.21 and
# go1.20.14 can't parse it). go1.20.14 is the last Go release supporting
# Windows 7 SP1/8/8.1/Server 2008 R2-2012 R2. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
Log "Building Legacy Windows agent binary (go1.20.14, amd64 only)..."
$LegacyAgentDir = Join-Path $RepoRoot "agent-legacy"
Push-Location $LegacyAgentDir
$env:GOTOOLCHAIN = "go1.20.14"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
# go1.20.14 predates Go workspace support (added in Go 1.21) and cannot
# parse the repo-root go.work file at all -- it errors on the go.work
# `go` directive's version format before it can even determine
# agent-legacy is (or isn't) a workspace member. GOWORK=off makes this
# build step ignore go.work entirely, exactly as it did before go.work
# existed.
$env:GOWORK = "off"

$legacyGoVersion = (go version)
Log "  Resolved toolchain: $legacyGoVersion"
if ($legacyGoVersion -notmatch "go1\.20\.14") {
    Pop-Location
    Err "Legacy agent toolchain mismatch. Expected go1.20.14, got: $legacyGoVersion"
}

go build -trimpath -ldflags="-s -w" -o "$OutDir\bas-agent-windows-legacy-amd64.exe" . 2>&1
if ($LASTEXITCODE -ne 0) {
    Warn "Legacy Windows agent build failed."
} else {
    $legacySizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-legacy-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-legacy-amd64.exe (${legacySizeMB}MB)"
}
$env:GOTOOLCHAIN = ""; $env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""; $env:GOWORK = ""
Pop-Location

# -- 5d. Sign Windows executables (D1) ----------------------------------------
# verify-windows-signature.ps1 defines Test-AuthenticodeSignature, which
# Update-OrchestratorAgentArtifacts (step 5c, below) re-verifies signatures
# with before patching -- must be loaded before that call site, not only
# at 7c's later release gate where this file is also dot-sourced.
. "$RepoRoot\packaging\signing\verify-windows-signature.ps1"
. "$RepoRoot\packaging\signing\sign-orchestrator-artifacts.ps1"

# @(...) -- Where-Object on 0 or 1 surviving matches returns a bare scalar
# (or $null), not a single-element array; under this script's
# Set-StrictMode -Version Latest, ".Count" on that throws
# PropertyNotFoundStrict (verified empirically). @(...) forces array shape
# regardless of match count.
$WindowsArtifactsToSign = @(@(
    "$OutDir\BASAgent-Setup-$Version.exe",
    "$OutDir\bas-agent-windows-amd64.exe",
    "$OutDir\bas-agent-windows-legacy-amd64.exe"
) | Where-Object { Test-Path $_ })

# bas-agent-windows-amd64.exe was already signed above, before the
# installer embedded it (C4) -- signing it again here would embed a
# fresh RFC 3161 timestamp and break the byte-identity that fix
# depends on. $WindowsArtifactsToSign (the full list) still carries it
# through to step 7c's release-verification audit below; this list is
# only for the signing loop immediately following.
$WindowsArtifactsToSignNow = @($WindowsArtifactsToSign | Where-Object { $_ -notlike "*bas-agent-windows-amd64.exe" })

if ($WindowsCertThumbprint) {
    Log "Signing $($WindowsArtifactsToSignNow.Count) Windows executable(s)..."
    foreach ($artifact in $WindowsArtifactsToSignNow) {
        $signed = Invoke-AuthenticodeSigning -Path $artifact -CertThumbprint $WindowsCertThumbprint
        if (-not $signed -and $WindowsSigningRequired) {
            Err "Authenticode signing failed for $artifact and Windows signing is required for this build."
        } elseif (-not $signed) {
            Warn "Authenticode signing failed for $artifact (not required for this build -- continuing)."
        }
    }
} elseif ($WindowsSigningRequired) {
    Err "Windows signing is required for this build (customer build) but -WindowsCertThumbprint / BAS_WINDOWS_CERT_THUMBPRINT is not set."
} else {
    Warn "No Windows signing certificate configured -- executables will not be signed (dev build, not required)."
}

# The legacy agent's setup zip must be built from the SIGNED exe -- zipping
# it before 5d (the original order) shipped an unsigned copy inside the zip
# while release-verification.json reported the loose exe (signed
# separately) as Valid, a false audit record for the actual customer
# deliverable. Re-zip here, after signing, so the zip's contents match what
# the gate just verified.
if (Test-Path "$OutDir\bas-agent-windows-legacy-amd64.exe") {
    Compress-Archive -Path "$OutDir\bas-agent-windows-legacy-amd64.exe" -DestinationPath "$OutDir\bas-agent-windows-legacy-amd64-setup.zip" -Force
}

# -- 5b. Build Linux agent binaries (amd64 + arm64) --------------------------
# CGO_ENABLED=0: required for cross-compile from Windows. All platform-specific
# code (webview2, tray, UAC) lives in *_windows.go files  -  excluded automatically
# by the Go toolchain when GOOS=linux. The Linux binary is self-installing:
# running it as root copies itself to /usr/local/bin/bas-agent and writes
# /etc/systemd/system/bas-agent.service (see agent/service_linux.go).
Log "Building Linux agent binaries..."
Push-Location $AgentDir

$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -ldflags="-s -w" -o "$OutDir\bas-agent-linux-amd64" . 2>&1
if ($LASTEXITCODE -ne 0) {
    Warn "Linux amd64 agent build failed."
} else {
    $la64MB = [math]::Round((Get-Item "$OutDir\bas-agent-linux-amd64").Length / 1MB, 1)
    Log "  bas-agent-linux-amd64 (${la64MB}MB)"
}

$env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
go build -ldflags="-s -w" -o "$OutDir\bas-agent-linux-arm64" . 2>&1
if ($LASTEXITCODE -ne 0) {
    Warn "Linux arm64 agent build failed."
} else {
    $la32MB = [math]::Round((Get-Item "$OutDir\bas-agent-linux-arm64").Length / 1MB, 1)
    Log "  bas-agent-linux-arm64 (${la32MB}MB)"
}

$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Pop-Location

# -- 5c. Extract BINARIES.sha256 from the Docker image ----------------------
# BINARIES.sha256 is generated inside the Docker agent-builder stage (see
# Dockerfile) from the same binaries that endpoints download. Extracting from
# the image here ensures the bundle's manifest matches what agents actually run.
# The manifest is then RSA-signed so the orchestrator can detect tampering.
Log "Extracting BINARIES.sha256 from Docker image..."
$BinManifestPath = Join-Path $OutDir "BINARIES.sha256"
# distroless has no shell/cat - use docker create+cp which works at filesystem level.
$tmpCID = docker create $OrchestratorTag 2>$null
if ($LASTEXITCODE -ne 0) {
    # A required build can't fall through to Update-OrchestratorAgentArtifacts
    # at all when this branch is taken (it's never called below) -- without
    # this Err, a customer build whose image lost its manifest would ship
    # Docker-built unsigned Windows binaries with exit code 0.
    if ($WindowsSigningRequired) { Err "  docker create failed - cannot extract manifest, and Windows signing is required for this build." }
    else { Warn "  docker create failed - cannot extract manifest. Agent integrity checks disabled." }
} else {
    docker cp "${tmpCID}:/agents/BINARIES.sha256" $BinManifestPath 2>$null | Out-Null
    $cpExit = $LASTEXITCODE
    docker rm $tmpCID 2>$null | Out-Null
    if ($cpExit -ne 0 -or -not (Test-Path $BinManifestPath) -or (Get-Item $BinManifestPath).Length -eq 0) {
        if ($WindowsSigningRequired) { Err "  Could not extract BINARIES.sha256 from image, and Windows signing is required for this build." }
        else { Warn "  Could not extract BINARIES.sha256 from image - agent integrity checks disabled." }
    } else {
        $entryCount = (Get-Content $BinManifestPath | Where-Object { $_ -ne "" }).Count
        Log "  $entryCount entries extracted from image"

        # RSA-sign so the orchestrator verifies the manifest was not tampered in transit.
        Push-Location $OrchestratorDir
        go run scripts/signer.go sign private_key.pem $BinManifestPath
        $binManExit = $LASTEXITCODE
        Pop-Location
        if ($binManExit -ne 0) {
            Warn "  RSA signing of BINARIES.sha256 failed."
        } else {
            Log "  BINARIES.sha256.sig written."
        }

        # Stage into orchestrator/agents/ for the Docker image and step 0b-iii signing.
        $AgentsStageDir = Join-Path $OrchestratorDir "agents"
        New-Item -ItemType Directory -Force -Path $AgentsStageDir | Out-Null
        Copy-Item $BinManifestPath "$AgentsStageDir\BINARIES.sha256" -Force
        if (Test-Path "$BinManifestPath.sig") {
            Copy-Item "$BinManifestPath.sig" "$AgentsStageDir\BINARIES.sha256.sig" -Force
        }

        # 0b-iii. Sign the staged manifest with the RSA key (runs here so the
        # file is guaranteed to exist - it was just written by the extract above).
        Log "  Signing BINARIES.sha256 manifest..."
        Push-Location $OrchestratorDir
        go run scripts/signer.go sign private_key.pem "agents\BINARIES.sha256"
        $manExit = $LASTEXITCODE
        Pop-Location
        if ($manExit -ne 0) { Err "Failed to sign BINARIES.sha256." }
        else { Log "  Manifest signed." }

        # C2: inject D1's signed Windows artifacts (and a manifest that
        # covers them) into the orchestrator image, in the same one-layer
        # patch this section already used for just the signature. This
        # replaces that narrower patch -- it's now folded into the richer
        # one below, which also bakes BINARIES.sha256.sig.
        $orchestratorPatched = Update-OrchestratorAgentArtifacts -OrchestratorTag $OrchestratorTag `
            -OutDir $OutDir -Version $Version -OrchestratorDir $OrchestratorDir -ExpectedThumbprint $WindowsCertThumbprint
        if ($orchestratorPatched -ne $true -and $WindowsSigningRequired) {
            Err "Failed to inject signed Windows artifacts into the orchestrator image, and Windows signing is required for this build."
        } elseif ($orchestratorPatched -ne $true) {
            Warn "  Could not inject signed Windows artifacts into the orchestrator image (not required for this build) -- it will serve its own independently-built, unsigned copies."
        } else {
            Log "  Signed Windows artifacts + regenerated BINARIES.sha256 baked into $OrchestratorTag."
        }
    }
}

# Save the orchestrator image AFTER the patch above, not before --
# docker save produced the tar that install.sh actually `docker load`s on
# the customer's machine, and saving it before this patch (the original
# order) meant the shipped tar never contained the patched bytes at all,
# even though the local daemon's tag was correctly patched. One save
# call now covers every path: patched-and-required, patched-not-required,
# skipped-not-required, and plain dev build with no cert at all.
Log "  Saving $OrchestratorTag..."
docker save $OrchestratorTag -o "$OutDir\images\bas-orchestrator-$Version.tar"
if ($LASTEXITCODE -ne 0) { Err "Failed to save orchestrator image." }
$orchSizeMB = [math]::Round((Get-Item "$OutDir\images\bas-orchestrator-$Version.tar").Length / 1MB)
Log "  Saved: bas-orchestrator-$Version.tar (${orchSizeMB}MB)"

# Copy manifest alongside the standalone Windows exe as a side-by-side fallback.
# If rsrc.syso was not generated, Windows will use this external manifest file
# when the user runs bas_agent_windows.exe directly.
Copy-Item "$AgentDir\bas_agent.exe.manifest" "$OutDir\bas-agent-windows-amd64.exe.manifest" -ErrorAction SilentlyContinue
Log "  Manifest copied: bas-agent-windows-amd64.exe.manifest (side-by-side fallback)"

# -- 5. Copy installer files --------------------------------------------------
Log "Copying installer files..."

$ComposeDir = Join-Path $RepoRoot "packaging\compose"
Copy-Item "$ComposeDir\install.sh"              "$OutDir\install.sh"
Copy-Item "$ComposeDir\uninstall.sh"            "$OutDir\uninstall.sh"
Copy-Item "$ComposeDir\setup.conf.template"     "$OutDir\setup.conf.template"
# Ship setup.conf as a ready-to-edit copy of the template so operators can
# run 'nano setup.conf' immediately without a manual cp step first.
Copy-Item "$ComposeDir\setup.conf.template"     "$OutDir\setup.conf"
Copy-Item "$ComposeDir\docker-compose.yml"      "$OutDir\docker-compose.yml"
# Stamp the real release version into the shipped .env.example so it never
# shows a stale placeholder inside a versioned bundle (was hardcoded 1.7.1
# regardless of $Version -- confused customers diffing it against the real
# generated .env, which correctly shows the actual build version). Read
# -Raw + WriteAllText (not Get-Content|Set-Content) for the same reason the
# VERSION/verify.sh writes below do it this way: avoids the BOM Out-File/
# Set-Content add on PS 5.1, which would corrupt the file for install.sh.
$envExampleText = (Get-Content "$ComposeDir\.env.example" -Raw) -replace "`r`n", "`n" `
    -replace '(?m)^BAS_VERSION=.*$', "BAS_VERSION=$Version"
[System.IO.File]::WriteAllText("$OutDir\.env.example", $envExampleText)
Copy-Item "$ComposeDir\systemd\bas-compose.service" "$OutDir\systemd\bas-compose.service"

# Generate a ready-to-use .env with random secrets so that a bare
# 'docker compose up -d' works without going through install.sh first.
# install.sh --install overwrites this with values from setup.conf.
function New-RandomHex { param([int]$bytes)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = [byte[]]::new($bytes)
    $rng.GetBytes($buf)
    ($buf | ForEach-Object { $_.ToString('x2') }) -join ''
}
$envContent = @"
# Audspect BAS -- Runtime environment
# Auto-generated by windows-build.ps1 v${Version}.
# Secrets below are unique to this build. Run install.sh --install to
# replace them with values from setup.conf (recommended for production).
BAS_VERSION=${Version}
COMPOSE_PROJECT_NAME=audspect
POSTGRES_DB=bas_platform
POSTGRES_USER=bas_user
POSTGRES_PASSWORD=$(New-RandomHex 16)
JWT_SECRET=$(New-RandomHex 32)
AGENT_SECRET=$(New-RandomHex 24)
CALDERA_API_KEY=$(New-RandomHex 20)
CALDERA_API_KEY_BLUE=$(New-RandomHex 20)
BAS_ADMIN_PASSWORD=
BAS_ADMIN_EMAIL=
BAS_PORT=9443
BAS_TLS=false
TLS_CERT=
TLS_KEY=
DATA_DIR=/opt/audspect
LOG_RETENTION_DAYS=90
SHARPHOUND_DIR=./sharphound
"@
# Write with Unix LF — docker compose runs on Linux
[System.IO.File]::WriteAllText("$OutDir\.env", ($envContent -replace "`r`n", "`n"))
Log "  Generated .env with random secrets (BAS_VERSION=${Version})"

# Normalize the Linux-targeted scripts/config to LF. (verify.sh / verify-sig.sh
# are normalized at their own copy sites below.)
foreach ($f in @("install.sh", "uninstall.sh", "setup.conf", "setup.conf.template", ".env.example",
                 "docker-compose.yml", "systemd\bas-compose.service")) {
    ConvertToLF (Join-Path $OutDir $f)
}
Log "  Normalized bundled shell/config files to LF"

# -- 6. Copy scenarios and wwwroot (if present) --------------------------------
$ScenariosDir = Join-Path $RepoRoot "scenarios"
if (Test-Path $ScenariosDir) {
    New-Item -ItemType Directory -Force -Path "$OutDir\scenarios" | Out-Null
    Copy-Item "$ScenariosDir\*" "$OutDir\scenarios\" -Recurse -Force
    Log "  Copied scenarios"
}

$WwwrootDir = Join-Path $RepoRoot "orchestrator\wwwroot"
if (Test-Path $WwwrootDir) {
    New-Item -ItemType Directory -Force -Path "$OutDir\wwwroot" | Out-Null
    Copy-Item "$WwwrootDir\*" "$OutDir\wwwroot\" -Recurse -Force
    Log "  Copied wwwroot"
}

# -- 6b. Copy ART external payloads (gsecdump, etc.) ---------------------------
# Binaries staged on the build host in packaging\art-payloads are baked into the
# bundle; install.sh stages them and compose bind-mounts them to /art-payloads, so
# the client gets them automatically. Empty is fine (payload atomics skip).
$PayloadDir = Join-Path $RepoRoot "packaging\art-payloads"
$PayloadOut = Join-Path $OutDir "art-payloads"
New-Item -ItemType Directory -Force -Path $PayloadOut | Out-Null
if (Test-Path $PayloadDir) {
    # Only real executables/scripts are bundled  -  the staging folder may also hold
    # tool source trees, zips, installers and PDBs, none of which an atomic invokes.
    # Flattened, first-wins on duplicate basenames, matching the server's importer.
    $allow = @('.exe', '.dll', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js',
               '.hta', '.sys', '.com', '.scr', '.jar', '.py', '.sh')
    $payloadCount = 0
    Get-ChildItem $PayloadDir -File -Recurse |
        Where-Object { $allow -contains $_.Extension.ToLower() } |
        ForEach-Object {
            $dest = Join-Path $PayloadOut $_.Name
            if (-not (Test-Path $dest)) {
                Copy-Item $_.FullName $dest -Force
                $payloadCount++
            }
        }
    Log "  Copied ART payloads (binaries only): $payloadCount"
}

# -- 7. Write VERSION file ----------------------------------------------------
# WriteAllText ? UTF-8 without BOM. install.sh reads this to tag the images in
# .env; a BOM here (which Out-File -Encoding utf8 adds on PS 5.1) would corrupt
# the version string and break compose image resolution.
[System.IO.File]::WriteAllText("$OutDir\VERSION", $Version)

# -- 7c. Release gate (D1) -----------------------------------------------------
# Runs before the manifest (7b) so MANIFEST.sha256's hash listing actually
# covers release-verification.json -- generating the gate's own audit record
# after the manifest (the original order) left it outside the file the
# customer uses to verify bundle integrity.
. "$RepoRoot\packaging\signing\verify-windows-signature.ps1"
. "$RepoRoot\packaging\signing\verify-release.ps1"

$AuditRecordPath = Join-Path $OutDir "release-verification.json"
$releaseOk = Invoke-ReleaseVerification -WindowsArtifacts $WindowsArtifactsToSign `
    -WindowsSigningRequired $WindowsSigningRequired -RequireTimestamp $WindowsSigningRequired `
    -ExpectedThumbprint $WindowsCertThumbprint -Version $Version -AuditRecordPath $AuditRecordPath

if (-not $releaseOk) {
    Err "Release verification failed -- see $AuditRecordPath. Refusing to package an unsigned/invalid release."
}
Log "Release verification passed: $AuditRecordPath"

# -- 7b. Air-gap integrity: verify.sh + per-file SHA-256 manifest --------------
# Gives bas-install the same offline integrity guarantees as the dedicated
# bas-airgap bundle: a per-file manifest the client verifies after unzip.
Log "Generating integrity manifest..."
Copy-Item "$ComposeDir\verify.sh" "$OutDir\verify.sh"
# Normalize to LF so the script runs on Linux even if git checked it out CRLF.
$verifyText = (Get-Content "$OutDir\verify.sh" -Raw) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText("$OutDir\verify.sh", $verifyText)

# Client-facing verification guide — staged into the bundle so MANIFEST.sha256
# hash-covers it. A second copy is placed at the dist\ delivery root in step 9b
# so it is readable before unzip (when the Layer-1 GPG check actually happens).
if (Test-Path "$ComposeDir\VERIFY.md") {
    Copy-Item "$ComposeDir\VERIFY.md" "$OutDir\VERIFY.md"
    $verifyMdText = (Get-Content "$OutDir\VERIFY.md" -Raw) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText("$OutDir\VERIFY.md", $verifyMdText)
    Log "  Verification guide staged: VERIFY.md"
}

$ManifestPath = Join-Path $OutDir "MANIFEST.sha256"
$prefixLen = $OutDir.Length + 1
$lines = Get-ChildItem -Path $OutDir -Recurse -File |
    Where-Object { $_.Name -ne "MANIFEST.sha256" -and $_.Name -ne "setup.conf" } |
    ForEach-Object {
        $rel = $_.FullName.Substring($prefixLen).Replace('\', '/')
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLower()
        "$hash  $rel"
    } | Sort-Object
# sha256sum-compatible: "<hash><two spaces><relative/path>", LF line endings, no BOM.
[System.IO.File]::WriteAllText($ManifestPath, ($lines -join "`n") + "`n")
Log "  MANIFEST.sha256 generated ($($lines.Count) files indexed)"

# -- 8. Generate license ------------------------------------------------------
$LicensePath = ""
if ($Customer -ne "" -and $CustomerID -ne "") {
    Log "Generating license for $Customer ($CustomerID) - valid $Days days..."
    $LicGenDir    = Join-Path $RepoRoot "packaging\licensing\licensegen"
    $LicPrivKey   = Join-Path $RepoRoot "packaging\licensing\keys\private.pem"

    if (-not (Test-Path $LicPrivKey)) {
        Warn "License private key not found at $LicPrivKey - skipping license generation."
        Warn "Run: cd packaging\licensing && bash keygen.sh"
    } else {
        Push-Location $RepoRoot
        go run "$LicGenDir\main.go" `
            -customer $Customer `
            -id       $CustomerID `
            -days     $Days `
            -key      $LicPrivKey `
            -out      "$CustomerID.lic"
        Pop-Location
        $LicensePath = Join-Path $RepoRoot "$CustomerID.lic"
        if (Test-Path $LicensePath) {
            Log "  License: $LicensePath"
            Copy-Item $LicensePath "$OutDir\$CustomerID.lic"
            # Shipped under its own customer-ID filename only -- no bas.lic
            # duplicate needed. docker-compose.yml now derives its mount and
            # BAS_LICENSE_PATH from LICENSE_FILE (install.sh's
            # _resolve_license_file sets this automatically from whatever
            # LIC_PATH the operator points at in setup.conf, e.g. this exact
            # $CustomerID.lic file), so there's nothing to hardcode here.
            Log "  License shipped as $CustomerID.lic"
        }
    }
} else {
    Warn "No -Customer / -CustomerID provided - skipping license generation."
    Warn "Generate manually: go run packaging\licensing\licensegen\main.go -customer '...' -id '...' -days 365"
}

# -- 9. Create ZIP for transfer -----------------------------------------------
Log "Creating ZIP: $ZipPath"
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path $OutDir -DestinationPath $ZipPath -Force
$ZipSizeMB = [math]::Round((Get-Item $ZipPath).Length / 1MB)
Log "  ZIP: $ZipPath ($ZipSizeMB MB)"

# Bundle-level checksum so the transfer itself is verifiable before unzip.
# sha256sum-compatible line: "<hash>  <filename>" (filename only, no path).
$zipHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
[System.IO.File]::WriteAllText("$ZipPath.sha256", "$zipHash  $(Split-Path -Leaf $ZipPath)`n")
Log "  Checksum: $ZipPath.sha256"

# Stage the verification guide at the delivery root too, so the client can read
# it BEFORE unzipping (when the Layer-1 GPG check happens). Unconditional — the
# guide ships even when GPG signing is skipped. A hash-covered copy is already
# inside the zip (step 7b).
if (Test-Path "$ComposeDir\VERIFY.md") {
    Copy-Item "$ComposeDir\VERIFY.md" "$DistDir\VERIFY.md" -Force
    $distVerifyMd = (Get-Content "$DistDir\VERIFY.md" -Raw) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText("$DistDir\VERIFY.md", $distVerifyMd)
    Log "  Verification guide staged in dist\: VERIFY.md"
}

# -- 9b. GPG-sign the bundle (skipped gracefully if no signing key) ------------
# Produces bas-install-<version>.zip.asc and stages a self-contained verify kit
# (pubkey.asc + verify-sig.sh) in dist\ so the client can authenticate the zip
# before unzip. The private key lives only in this host's GPG keyring.
#
# Remove-UnsignedDeliverable: Err() below exits without cleanup, so a
# required-GPG-signing failure previously left the just-built ZIP and its
# .sha256 sitting in dist\ looking like a normal deliverable even though the
# build had failed closed. Called before every required-failure Err in this
# section.
function Remove-UnsignedDeliverable {
    Remove-Item -Force -ErrorAction SilentlyContinue $ZipPath, "$ZipPath.sha256"
}
$Signed = $false
$SigningDir      = Join-Path $RepoRoot "packaging\signing"
$SigningKeyEmail = "releases@audspect.com"
# Prefer a full GnuPG (Gpg4win) over the Git-for-Windows MSYS gpg: the latter's
# keyboxd is not launchable from a PowerShell (non-MSYS) context, so a keyboxd-
# backed keyring fails here. (If you hit "error running keyboxd", disable it:
# remove 'use-keyboxd' from %USERPROFILE%\.gnupg\common.conf and re-import the
# public key so gpg uses a classic in-process pubring.kbx.)
$gpgExe = $null
foreach ($cand in @("C:\Program Files (x86)\GnuPG\bin\gpg.exe", "C:\Program Files\GnuPG\bin\gpg.exe")) {
    if (-not $gpgExe -and (Test-Path $cand)) { $gpgExe = $cand }
}
if (-not $gpgExe) {
    $gpgCmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($gpgCmd) { $gpgExe = $gpgCmd.Source }
    elseif (Test-Path "C:\Program Files\Git\usr\bin\gpg.exe") { $gpgExe = "C:\Program Files\Git\usr\bin\gpg.exe" }
}

if (-not $gpgExe) {
    if ($GpgSigningRequired) {
        Remove-UnsignedDeliverable
        Err "gpg not found and GPG signing is required for this build. Install Gpg4win or Git for Windows."
    } else {
        Warn "gpg not found - bundle is unsigned. Install Gpg4win or Git for Windows to enable signing."
    }
} else {
    # gpg writes progress to stderr; with $ErrorActionPreference='Stop' (set above)
    # PowerShell turns native stderr into a terminating NativeCommandError, which
    # would abort the whole build over a mere signing hiccup. Run the native gpg
    # calls under 'Continue' so a missing key or a broken gpg only SKIPS signing.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $gpgExe --list-secret-keys $SigningKeyEmail 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            if ($GpgSigningRequired) {
                Remove-UnsignedDeliverable
                Err "No usable GPG signing key for $SigningKeyEmail (gpg exit $LASTEXITCODE) and GPG signing is required for this build. Generate one: bash packaging/signing/keygen.sh"
            } else {
                Warn "No usable signing key for $SigningKeyEmail (gpg exit $LASTEXITCODE) - bundle is unsigned."
                Warn "  Generate one: bash packaging/signing/keygen.sh"
            }
        } else {
            Log "Signing bundle with GPG key $SigningKeyEmail..."
            $SigPath = "$ZipPath.asc"
            if (Test-Path $SigPath) { Remove-Item -Force $SigPath }
            & $gpgExe --armor --batch --yes --detach-sign `
                --local-user $SigningKeyEmail --output $SigPath $ZipPath 2>$null
            if ($LASTEXITCODE -eq 0 -and (Test-Path $SigPath)) {
                $Signed = $true
                Log "  Signature: $SigPath"
                # Self-contained verify kit alongside the zip (verify-sig.sh reads
                # pubkey.asc from its own directory).
                Copy-Item "$SigningDir\pubkey.asc"    "$DistDir\pubkey.asc"    -Force
                Copy-Item "$SigningDir\verify-sig.sh" "$DistDir\verify-sig.sh" -Force
                $vsText = (Get-Content "$DistDir\verify-sig.sh" -Raw) -replace "`r`n", "`n"
                [System.IO.File]::WriteAllText("$DistDir\verify-sig.sh", $vsText)
                Log "  Verify kit staged in dist\: pubkey.asc + verify-sig.sh"
            } elseif ($GpgSigningRequired) {
                Remove-UnsignedDeliverable
                Err "GPG signing failed (exit $LASTEXITCODE) and GPG signing is required for this build."
            } else {
                Warn "  GPG signing failed (exit $LASTEXITCODE) - bundle is unsigned."
            }
        }
    } catch {
        # This catch previously always Warned regardless of GpgSigningRequired
        # -- a required build whose gpg invocation threw (rather than merely
        # exiting nonzero) silently shipped unsigned instead of failing closed.
        if ($GpgSigningRequired) {
            Remove-UnsignedDeliverable
            Err "GPG signing failed (gpg error: $($_.Exception.Message)) and GPG signing is required for this build."
        } else {
            Warn "  GPG signing skipped (gpg error: $($_.Exception.Message)) - bundle is unsigned."
        }
    } finally {
        $ErrorActionPreference = $prevEAP
    }
}

# -- 10. Summary --------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  BAS Platform v$Version -- Client Delivery Package Ready"   -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
$zipLeaf = Split-Path -Leaf $ZipPath
Write-Host "  Package ZIP : $ZipPath"
Write-Host "  Checksum    : $ZipPath.sha256"
if ($Signed) {
    Write-Host "  Signature   : $ZipPath.asc  (GPG, $SigningKeyEmail)"
}
if ($LicensePath -ne "" -and (Test-Path $LicensePath)) {
    Write-Host "  License     : $LicensePath"
}
Write-Host ""
Write-Host "  Transfer to client server:" -ForegroundColor Yellow
if ($Signed) {
    Write-Host "    scp -i <key.pem> `"$ZipPath`" `"$ZipPath.sha256`" `"$ZipPath.asc`" `"$DistDir\pubkey.asc`" `"$DistDir\verify-sig.sh`" ubuntu@<client-ip>:~/"
} else {
    Write-Host "    scp -i <key.pem> `"$ZipPath`" `"$ZipPath.sha256`" ubuntu@<client-ip>:~/"
}
if ($LicensePath -ne "" -and (Test-Path $LicensePath)) {
    Write-Host "    scp -i <key.pem> `"$LicensePath`" ubuntu@<client-ip>:~/"
}
Write-Host ""
Write-Host "  Client runs (on their Ubuntu server):" -ForegroundColor Yellow
if ($Signed) {
    Write-Host "    bash verify-sig.sh $zipLeaf            # verify signature + sha256"
} else {
    Write-Host "    sha256sum -c $zipLeaf.sha256   # verify transfer"
}
Write-Host "    unzip $zipLeaf"
Write-Host "    cd $OutName && bash verify.sh                       # verify file integrity"
Write-Host "    cp setup.conf.template setup.conf && vi setup.conf  # fill in values"
Write-Host "    sudo bash install.sh --check --config setup.conf    # attach output to CAB"
Write-Host "    sudo bash install.sh --install --config setup.conf"
Write-Host ""
