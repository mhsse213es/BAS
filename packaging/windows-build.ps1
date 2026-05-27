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

# -- 1. Build Docker image ----------------------------------------------------
$OrchestratorTag = "bas-orchestrator:$Version"

if (-not $SkipBuild) {
    Log "Building $OrchestratorTag (garble -literals -tiny - this takes 5-10 min)..."
    docker build -t $OrchestratorTag -f "$RepoRoot\orchestrator\Dockerfile" $RepoRoot
    if ($LASTEXITCODE -ne 0) { Err "Docker build failed." }
    Log "Image built: $OrchestratorTag"
} else {
    Warn "Skipping image build (-SkipBuild). Using existing $OrchestratorTag."
}

# -- 2. Pull dependency images ------------------------------------------------
Log "Pulling postgres:16-alpine..."
docker pull postgres:16-alpine
if ($LASTEXITCODE -ne 0) { Err "Failed to pull postgres:16-alpine." }

Log "Pulling ghcr.io/mitre/caldera:latest..."
docker pull ghcr.io/mitre/caldera:latest
if ($LASTEXITCODE -ne 0) { Warn "Failed to pull Caldera image - bundle will exclude it." }

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

$calderaExists = docker image inspect "ghcr.io/mitre/caldera:latest" 2>$null
if ($calderaExists) {
    Log "  Saving ghcr.io/mitre/caldera:latest..."
    docker save ghcr.io/mitre/caldera:latest -o "$OutDir\images\caldera-latest.tar"
    Log "  Saved: caldera-latest.tar"
} else {
    Warn "Caldera image not available - skipping. Setup will pull it if internet is available."
}

# -- 5. Copy installer files --------------------------------------------------
Log "Copying installer files..."

$ComposeDir = Join-Path $RepoRoot "packaging\compose"
Copy-Item "$ComposeDir\setup.sh"                "$OutDir\setup.sh"
Copy-Item "$ComposeDir\docker-compose.yml"      "$OutDir\docker-compose.yml"
Copy-Item "$ComposeDir\docker-compose.prod.yml" "$OutDir\docker-compose.prod.yml"
Copy-Item "$ComposeDir\.env.example"            "$OutDir\.env.example"
Copy-Item "$ComposeDir\systemd\bas-compose.service" "$OutDir\systemd\bas-compose.service"

if (Test-Path "$ComposeDir\uninstall.sh") {
    Copy-Item "$ComposeDir\uninstall.sh" "$OutDir\uninstall.sh"
}

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

# -- 7. Write VERSION file ----------------------------------------------------
$Version | Out-File -FilePath "$OutDir\VERSION" -Encoding utf8 -NoNewline

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

# -- 10. Summary --------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  BAS Platform v$Version -- Client Delivery Package Ready"   -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Package ZIP : $ZipPath"
if ($LicensePath -ne "" -and (Test-Path $LicensePath)) {
    Write-Host "  License     : $LicensePath"
}
Write-Host ""
Write-Host "  Transfer to client server:" -ForegroundColor Yellow
Write-Host "    scp -i <key.pem> `"$ZipPath`" ubuntu@<client-ip>:~/"
if ($LicensePath -ne "" -and (Test-Path $LicensePath)) {
    Write-Host "    scp -i <key.pem> `"$LicensePath`" ubuntu@<client-ip>:~/"
}
Write-Host ""
Write-Host "  Client runs (on their Ubuntu server):" -ForegroundColor Yellow
Write-Host "    unzip $(Split-Path -Leaf $ZipPath)"
Write-Host "    sudo bash $OutName/setup.sh --offline"
Write-Host ""
