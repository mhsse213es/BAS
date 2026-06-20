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
    [switch] $SkipBuild          # pass -SkipBuild to repackage without rebuilding image
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
        $t = (Get-Content $path -Raw) -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText($path, $t)
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
# the COPY context. The private key never leaves this host — only the public
# key (compiled into the binary) is distributed to clients.
#
# Key lifecycle:
#   First run: generates RSA-4096 private_key.pem in orchestrator\ and injects
#              the matching public key into orchestrator\internal\integrity\signing.go
#   Subsequent runs: re-uses existing key (skips keygen)
#   CRITICAL: back up orchestrator\private_key.pem — losing it means scenarios
#             can never be validly re-signed.

$OrchestratorDir = Join-Path $RepoRoot "orchestrator"
$PrivKeyPath     = Join-Path $OrchestratorDir "private_key.pem"
$ScenariosDir    = Join-Path $RepoRoot "scenarios"

Log "Content signing pre-build..."

# 0b-i. RSA keypair — idempotent: only runs once per install.
if (-not (Test-Path $PrivKeyPath)) {
    Log "  No private_key.pem found. Generating RSA-4096 keypair..."
    Push-Location $OrchestratorDir
    go run scripts/signer.go keygen
    $kgExit = $LASTEXITCODE
    Pop-Location
    if ($kgExit -ne 0) { Err "RSA keygen failed — check Go is installed and orchestrator/scripts/signer.go exists." }
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
    Warn "  No scenarios\ directory found at repo root — skipping scenario signing."
}

# 0b-iii. Sign BINARIES.sha256 manifest (if present).
$ManifestFile = Join-Path $OrchestratorDir "agents\BINARIES.sha256"
if (Test-Path $ManifestFile) {
    Log "  Signing BINARIES.sha256 manifest..."
    Push-Location $OrchestratorDir
    go run scripts/signer.go sign private_key.pem "agents\BINARIES.sha256"
    $manExit = $LASTEXITCODE
    Pop-Location
    if ($manExit -ne 0) { Err "Failed to sign BINARIES.sha256." }
    Log "  Manifest signed."
} else {
    Warn "  No agents\BINARIES.sha256 found — skipping manifest signing."
}

# 0b-iv. SHA-256 hash of wwwroot/index.html, injected into the binary via
#        --build-arg BAS_WWWROOT_HASH so StaticHandler() halts on mismatch.
$WWWRootHash = ""
$IndexHtmlPath = Join-Path $OrchestratorDir "wwwroot\index.html"
if (Test-Path $IndexHtmlPath) {
    $WWWRootHash = (Get-FileHash -Path $IndexHtmlPath -Algorithm SHA256).Hash.ToLower()
    Log "  wwwroot/index.html hash: $($WWWRootHash.Substring(0,16))..."
} else {
    Warn "  wwwroot/index.html not found — UI tamper-detection will be DISABLED in this build."
}

# -- 1. Build Docker image ----------------------------------------------------
$OrchestratorTag = "bas-orchestrator:$Version"

if (-not $SkipBuild) {
    # Obfuscation (garble -literals -tiny, scoped to our module via GOGARBLE) runs
    # inside orchestrator/Dockerfile — see that file for the GOGARBLE rationale.
    # BAS_WWWROOT_HASH is injected via -X ldflags so StaticHandler() verifies the
    # dashboard SPA hash at startup. BAS_SIGNING_KEY is not needed — the public key
    # was already compiled into signing.go by step 0b-i above.
    Log "Building $OrchestratorTag (garble -literals -tiny - this takes 5-10 min)..."
    $buildExtraArgs = @("--build-arg", "BAS_VERSION=$Version")
    if ($WWWRootHash -ne "") {
        $buildExtraArgs += @("--build-arg", "BAS_WWWROOT_HASH=$WWWRootHash")
    }
    docker build -t $OrchestratorTag @buildExtraArgs -f "$RepoRoot\orchestrator\Dockerfile" $RepoRoot
    if ($LASTEXITCODE -ne 0) { Err "Docker build failed." }
    Log "Image built: $OrchestratorTag"
} else {
    Warn "Skipping image build (-SkipBuild). Using existing $OrchestratorTag."
    if ($WWWRootHash -eq "") { Warn "  (UI tamper hash was not computed — existing image retains its compiled hash)" }
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
docker build -t "bas-caldera:$Version" "$RepoRoot\packaging\caldera"
if ($LASTEXITCODE -ne 0) { Warn "Failed to build bas-caldera image - bundle will fall back to stock Caldera." }

# -- 3. Create output directory structure -------------------------------------
Log "Staging delivery package: $OutDir"
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force -Path "$OutDir\images" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutDir\systemd" | Out-Null

# -- 4. Save Docker images (.tar -- docker load accepts both .tar and .tar.gz) -
Log "Saving Docker images (this may take a few minutes)..."

Log "  Saving $OrchestratorTag..."
docker save $OrchestratorTag -o "$OutDir\images\bas-orchestrator-$Version.tar"
if ($LASTEXITCODE -ne 0) { Err "Failed to save orchestrator image." }
$sizeMB = [math]::Round((Get-Item "$OutDir\images\bas-orchestrator-$Version.tar").Length / 1MB)
Log "  Saved: bas-orchestrator-$Version.tar (${sizeMB}MB)"

Log "  Saving postgres:16-alpine..."
docker save postgres:16-alpine -o "$OutDir\images\postgres-16-alpine.tar"
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
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags="-s -w" -o "$InstallerDir\bas_agent.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Err "Agent build failed." }
$env:GOOS = ""; $env:GOARCH = ""
Pop-Location
Log "  Agent binary built: installer\bas_agent.exe"

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

# Also build standalone Windows agent (for manual / side-by-side deploy)
Log "Building standalone Windows agent binary..."
Push-Location $AgentDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -ldflags="-s -w" -o "$OutDir\bas-agent-windows-amd64.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Warn "Standalone Windows agent build failed." }
else {
    $wSizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-amd64.exe (${wSizeMB}MB)"
}
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Pop-Location

# -- 5b. Build Linux agent binaries (amd64 + arm64) --------------------------
# CGO_ENABLED=0: required for cross-compile from Windows. All platform-specific
# code (webview2, tray, UAC) lives in *_windows.go files — excluded automatically
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

# Copy manifest alongside the standalone Windows exe as a side-by-side fallback.
# If rsrc.syso was not generated, Windows will use this external manifest file
# when the user runs bas_agent_windows.exe directly.
Copy-Item "$AgentDir\bas_agent.exe.manifest" "$OutDir\bas-agent-windows-amd64.exe.manifest" -ErrorAction SilentlyContinue
Log "  Manifest copied: bas-agent-windows-amd64.exe.manifest (side-by-side fallback)"

# -- 5. Copy installer files --------------------------------------------------
Log "Copying installer files..."

$ComposeDir = Join-Path $RepoRoot "packaging\compose"
Copy-Item "$ComposeDir\install.sh"              "$OutDir\install.sh"
Copy-Item "$ComposeDir\setup.conf.template"     "$OutDir\setup.conf.template"
Copy-Item "$ComposeDir\docker-compose.yml"      "$OutDir\docker-compose.yml"
Copy-Item "$ComposeDir\.env.example"            "$OutDir\.env.example"
Copy-Item "$ComposeDir\systemd\bas-compose.service" "$OutDir\systemd\bas-compose.service"

# Normalize the Linux-targeted scripts/config to LF. (verify.sh / verify-sig.sh
# are normalized at their own copy sites below.)
foreach ($f in @("install.sh", "setup.conf.template", ".env.example",
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
    # Only real executables/scripts are bundled — the staging folder may also hold
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
# WriteAllText → UTF-8 without BOM. install.sh reads this to tag the images in
# .env; a BOM here (which Out-File -Encoding utf8 adds on PS 5.1) would corrupt
# the version string and break compose image resolution.
[System.IO.File]::WriteAllText("$OutDir\VERSION", $Version)

# -- 7b. Air-gap integrity: verify.sh + per-file SHA-256 manifest --------------
# Gives bas-install the same offline integrity guarantees as the dedicated
# bas-airgap bundle: a per-file manifest the client verifies after unzip.
Log "Generating integrity manifest..."
Copy-Item "$ComposeDir\verify.sh" "$OutDir\verify.sh"
# Normalize to LF so the script runs on Linux even if git checked it out CRLF.
$verifyText = (Get-Content "$OutDir\verify.sh" -Raw) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText("$OutDir\verify.sh", $verifyText)

$ManifestPath = Join-Path $OutDir "MANIFEST.sha256"
$prefixLen = $OutDir.Length + 1
$lines = Get-ChildItem -Path $OutDir -Recurse -File |
    Where-Object { $_.Name -ne "MANIFEST.sha256" } |
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
    $LicGenDir   = Join-Path $RepoRoot "packaging\licensing\licensegen"
    $PrivKeyPath = Join-Path $RepoRoot "packaging\licensing\keys\private.pem"

    if (-not (Test-Path $PrivKeyPath)) {
        Warn "Private key not found at $PrivKeyPath - skipping license generation."
        Warn "Run: cd packaging\licensing && bash keygen.sh"
    } else {
        Push-Location $RepoRoot
        go run "$LicGenDir\main.go" `
            -customer $Customer `
            -id       $CustomerID `
            -days     $Days `
            -key      $PrivKeyPath `
            -out      "$CustomerID.lic"
        Pop-Location
        $LicensePath = Join-Path $RepoRoot "$CustomerID.lic"
        if (Test-Path $LicensePath) {
            Log "  License: $LicensePath"
            Copy-Item $LicensePath "$OutDir\$CustomerID.lic"
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

# -- 9b. GPG-sign the bundle (skipped gracefully if no signing key) ------------
# Produces bas-install-<version>.zip.asc and stages a self-contained verify kit
# (pubkey.asc + verify-sig.sh) in dist\ so the client can authenticate the zip
# before unzip. The private key lives only in this host's GPG keyring.
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
    Warn "gpg not found - bundle is unsigned. Install Gpg4win or Git for Windows to enable signing."
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
            Warn "No usable signing key for $SigningKeyEmail (gpg exit $LASTEXITCODE) - bundle is unsigned."
            Warn "  Generate one: bash packaging/signing/keygen.sh"
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
            } else {
                Warn "  GPG signing failed (exit $LASTEXITCODE) - bundle is unsigned."
            }
        }
    } catch {
        Warn "  GPG signing skipped (gpg error: $($_.Exception.Message)) - bundle is unsigned."
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
