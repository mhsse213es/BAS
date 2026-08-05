param(
    [string]$OutDir = "ag"
)

Write-Host "[*] Building BAS Windows Agent..."

Push-Location "$PSScriptRoot\..\agent"

# Fetch dependencies
Write-Host "[*] Fetching dependencies..."
go mod tidy
if ($LASTEXITCODE -ne 0) { Write-Host "[!] go mod tidy failed"; Pop-Location; exit 1 }

# Build Windows x64 binary
$env:GOOS   = "windows"
$env:GOARCH = "amd64"
$outPath = "..\$OutDir\bas_agent.exe"

Write-Host "[*] Compiling..."
# -H windowsgui: without this the agent is a console-subsystem binary and
# Windows auto-shows a console whenever it's launched without an inherited
# one (e.g. the tray's Run-key entry at logon) -- see packaging/windows-build.ps1.
go build -ldflags="-s -w -H windowsgui" -o $outPath .
if ($LASTEXITCODE -ne 0) { Write-Host "[!] Build failed"; Pop-Location; exit 1 }

Pop-Location

$size = [math]::Round((Get-Item "$PSScriptRoot\..\$OutDir\bas_agent.exe").Length / 1MB, 1)
Write-Host "[+] Built: $OutDir\bas_agent.exe ($size MB)"
Write-Host ""
Write-Host "Deploy to test machine:"
Write-Host "  1. Copy bas_agent.exe to the Windows machine"
Write-Host "  2. Open PowerShell as Administrator"
Write-Host "  3. Set-Item Env:BAS_SERVER_URL 'http://34.44.134.203:32077'"
Write-Host "  4. .\bas_agent.exe"
