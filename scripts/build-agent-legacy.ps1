# scripts/build-agent-legacy.ps1
param(
    [string]$OutDir = "ag-legacy"
)

Write-Host "[*] Building BAS Legacy Windows Agent..."

Push-Location "$PSScriptRoot\..\agent-legacy"

$env:GOTOOLCHAIN = "go1.20.14"

Write-Host "[*] Fetching dependencies..."
go mod tidy
if ($LASTEXITCODE -ne 0) { Write-Host "[!] go mod tidy failed"; Pop-Location; exit 1 }

# Hard assertion, not a log line: a silently-wrong toolchain here produces a
# binary linked against a runtime newer than the legacy OSes actually
# support, defeating the entire point of this build. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
# NOTE: go.mod must NOT have a `toolchain` directive -- that syntax
# predates Go 1.21 and go1.20.14 cannot parse it. GOTOOLCHAIN (set above)
# is the only pinning mechanism.
$goVersionOutput = (go version)
Write-Host "[*] Resolved toolchain: $goVersionOutput"
if ($goVersionOutput -notmatch "go1\.20\.14") {
    Write-Host "[!] Wrong toolchain resolved. Expected go1.20.14, got: $goVersionOutput"
    Write-Host "[!] Check that GOTOOLCHAIN=go1.20.14 is actually set -- go.mod must NOT have a toolchain directive."
    Pop-Location
    exit 1
}

$env:GOOS   = "windows"
$env:GOARCH = "amd64"
$outPath = "..\$OutDir\bas_agent_legacy.exe"

Write-Host "[*] Compiling..."
go build -ldflags="-s -w -H windowsgui" -o $outPath .
if ($LASTEXITCODE -ne 0) { Write-Host "[!] Build failed"; Pop-Location; exit 1 }

Pop-Location

$size = [math]::Round((Get-Item "$PSScriptRoot\..\$OutDir\bas_agent_legacy.exe").Length / 1MB, 1)
Write-Host "[+] Built: $OutDir\bas_agent_legacy.exe ($size MB)"
Write-Host ""
Write-Host "Deploy to a Windows 7 SP1 / Server 2008 R2+ test VM:"
Write-Host "  1. Copy bas_agent_legacy.exe to the VM"
Write-Host "  2. Open an elevated command prompt"
Write-Host "  3. bas_agent_legacy.exe --install --server http://<host>:9000 --secret <SECRET>"
