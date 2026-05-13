
# ============================================================
# Audspect BAS — One-Click Build & Package Script
# Run this from: C:\Users\Administrator\Downloads\1\
# Output:
#   ./PUBLISH_Server/  ← zip this and upload to Elastic Beanstalk
#   ./PUBLISH_Agent/   ← copy BASAgent.exe to target Windows machine
# ============================================================

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$serverDir = Join-Path $root "BAS.Server"
$agentDir  = Join-Path $root "BAS.Agent"
$outServer = Join-Path $root "PUBLISH_Server"
$outAgent  = Join-Path $root "PUBLISH_Agent"

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  Audspect BAS — Build & Publish Script" -ForegroundColor Cyan
Write-Host "==========================================`n" -ForegroundColor Cyan

# ── 1. Clean previous output ──────────────────────────────────
Remove-Item -Recurse -Force $outServer -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $outAgent  -ErrorAction SilentlyContinue

# ── 2. Publish SERVER (for AWS Elastic Beanstalk / Linux) ─────
Write-Host "[1/2] Publishing SERVER (linux-x64, self-contained)..." -ForegroundColor Yellow
dotnet publish "$serverDir/BAS.Server.csproj" `
    -c Release `
    -r linux-x64 `
    --self-contained true `
    -o "$outServer"

if ($LASTEXITCODE -ne 0) { Write-Host "SERVER PUBLISH FAILED" -ForegroundColor Red; exit 1 }
Write-Host "    Server published to: $outServer" -ForegroundColor Green

# ── 3. Publish AGENT (for Windows target machines) ────────────
Write-Host "`n[2/2] Publishing AGENT (win-x64, self-contained single exe)..." -ForegroundColor Yellow
dotnet publish "$agentDir/BAS.Agent.csproj" `
    -c Release `
    -r win-x64 `
    --self-contained true `
    /p:PublishSingleFile=true `
    -o "$outAgent"

if ($LASTEXITCODE -ne 0) { Write-Host "AGENT PUBLISH FAILED" -ForegroundColor Red; exit 1 }
Write-Host "    Agent published to: $outAgent" -ForegroundColor Green

# ── 4. Summary ────────────────────────────────────────────────
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  BUILD COMPLETE!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  SERVER  → Zip everything inside: $outServer"
Write-Host "            Then upload the .zip to Elastic Beanstalk"
Write-Host ""
Write-Host "  AGENT   → Copy to target machine: $outAgent\BASAgent.exe"
Write-Host "            Also copy: $outAgent\appsettings.json"
Write-Host ""
