<#
.SYNOPSIS
    Automated build script for Audspect BAS Orchestrator

.DESCRIPTION
    This script automates the full secure build pipeline for the orchestrator:
    1. Generates an RSA keypair if one doesn't exist.
    2. Signs all builtin scenarios (*.yaml) in the scenarios/ directory.
    3. Signs the BINARIES.sha256 manifest.
    4. Computes the SHA-256 hash of wwwroot/index.html for tamper detection.
    5. Injects the UI hash and compiles the final server binary.
#>

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Audspect BAS Orchestrator Secure Build Tool " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Key Generation
if (-not (Test-Path "private_key.pem")) {
    Write-Host "[*] No private_key.pem found. Generating new RSA-4096 keypair..." -ForegroundColor Yellow
    go run scripts/signer.go keygen
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Key generation failed." -ForegroundColor Red
        exit $LASTEXITCODE
    }
} else {
    Write-Host "[+] Found existing private_key.pem" -ForegroundColor Green
}

# 2. Sign Scenarios
# Scenarios live at the REPO ROOT (../scenarios relative to this script in
# orchestrator\). Fall back to orchestrator\scenarios\ for developers who keep a
# local copy there.
$scenariosDir = ""
if (Test-Path "..\scenarios") {
    $scenariosDir = "..\scenarios"
} elseif (Test-Path "scenarios") {
    $scenariosDir = "scenarios"
}

if ($scenariosDir -ne "") {
    $scenarios = Get-ChildItem -Path $scenariosDir -Filter "*.yaml" -Recurse -File
    if ($scenarios.Count -gt 0) {
        Write-Host "[*] Signing $($scenarios.Count) builtin scenario(s) in $scenariosDir..." -ForegroundColor Cyan
        foreach ($scenario in $scenarios) {
            go run scripts/signer.go sign private_key.pem $scenario.FullName
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[!] Failed to sign $($scenario.Name)" -ForegroundColor Red
                exit $LASTEXITCODE
            }
        }
    } else {
        Write-Host "[~] No *.yaml scenarios found in $scenariosDir" -ForegroundColor DarkGray
    }
} else {
    Write-Host "[~] No scenarios directory found (checked ..\scenarios and scenarios\). Skipping." -ForegroundColor DarkGray
}

# 3. Sign Manifest
if (Test-Path "agents/BINARIES.sha256") {
    Write-Host "[*] Signing BINARIES.sha256 manifest..." -ForegroundColor Cyan
    go run scripts/signer.go sign private_key.pem "agents/BINARIES.sha256"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to sign manifest." -ForegroundColor Red
        exit $LASTEXITCODE
    }
} else {
    Write-Host "[~] No agents/BINARIES.sha256 found to sign." -ForegroundColor DarkGray
}

# 4. Hash wwwroot/MANIFEST.sha256 (written by web/tools/dev-build.sh; it lists
#    the hash of every dashboard file, so this one hash anchors them all)
$manifestHash = ""
if (Test-Path "wwwroot/MANIFEST.sha256") {
    Write-Host "[*] Hashing wwwroot/MANIFEST.sha256..." -ForegroundColor Cyan
    $manifestHash = (Get-FileHash -Path "wwwroot/MANIFEST.sha256" -Algorithm SHA256).Hash.ToLower()
    Write-Host "[+] Computed hash: $($manifestHash.Substring(0,16))..." -ForegroundColor Green
} else {
    Write-Host "[!] wwwroot/MANIFEST.sha256 not found (run web/tools/dev-build.sh)! Skipping hash injection." -ForegroundColor Red
}

# 5. Build Binary
Write-Host "[*] Compiling server.exe with garble obfuscation..." -ForegroundColor Cyan
$ldflags = "-s -w"
if ($manifestHash -ne "") {
    $ldflags += " -X main.expectedWWWManifestHash=$manifestHash"
}

$env:CGO_ENABLED = "0"
garble -literals -tiny build -ldflags $ldflags -o server.exe ./cmd/server

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host " BUILD SUCCESSFUL" -ForegroundColor Green
    Write-Host " Output: .\server.exe" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
} else {
    Write-Host "[!] Build failed." -ForegroundColor Red
    exit $LASTEXITCODE
}
