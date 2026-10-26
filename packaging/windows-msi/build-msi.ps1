#requires -Version 5.1
<#
.SYNOPSIS
  Builds the Audspect Agent MSI: tests the custom actions, builds, validates, structure-checks and
  (optionally) signs it.

.DESCRIPTION
  Signing modes (mutually exclusive):
    -Release   Trusted code-signing certificate required (-CertThumbprint or $env:BAS_WINDOWS_CERT_THUMBPRINT),
               a real licence text (-EulaRtf, not the placeholder), and the result must verify as a valid
               Authenticode signature. Any shortfall stops the build before anything is produced.
    -DevSign   Signs with a throwaway self-signed certificate that is clearly labelled and NOT trusted.
               For lab testing only; the output is marked and a -Release build refuses to ship it.
    (neither)  Unsigned; allowed only for local development.

  Signing keys and certificates are never read from or written to the repository.
  The WiX toolchain is pinned by dotnet-tools.json (wix 5.0.2) and the UI extension version below.

.EXAMPLE
  .\build-msi.ps1 -AgentExe ..\..\installer\bas_agent.exe -Version 2.1.0 -DevSign
  .\build-msi.ps1 -AgentExe .\bas_agent.exe -Version 2.1.0 -Release -EulaRtf C:\owner\eula.rtf -CertThumbprint ABC...
#>
param(
    [Parameter(Mandatory)][string]$AgentExe,
    [Parameter(Mandatory)][string]$Version,
    [string]$OutDir,
    [string]$EulaRtf,
    [switch]$Release,
    [switch]$DevSign,
    [string]$CertThumbprint = $env:BAS_WINDOWS_CERT_THUMBPRINT,
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
# $PSScriptRoot is empty inside parameter defaults on Windows PowerShell 5.1, so defaults are applied here.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) { $OutDir = Join-Path $scriptDir 'out' }
if (-not $EulaRtf) { $EulaRtf = Join-Path $scriptDir 'eula.placeholder.rtf' }
$WixUiExtension = 'WixToolset.UI.wixext/5.0.2'
$MsiName = 'AudspectAgent-x64.msi'

function Fail([string]$m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }
function Step([string]$m) { Write-Host "[+] $m" -ForegroundColor Green }

# ---- guards: nothing expensive happens before these pass -------------------------------------
if ($Release -and $DevSign) { Fail '-Release and -DevSign are mutually exclusive.' }
if ($Version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') { Fail "Version '$Version' must look like 1.2.3 or 1.2.3.4." }
if (-not (Test-Path $AgentExe)) { Fail "Agent executable not found: $AgentExe" }
if (-not (Test-Path $EulaRtf)) { Fail "Licence file not found: $EulaRtf" }
$eulaText = Get-Content -Raw -Path $EulaRtf
$eulaIsPlaceholder = ($eulaText -match 'LICENCE TEXT NOT SUPPLIED') -or ((Split-Path -Leaf $EulaRtf) -like '*placeholder*')
if ($Release) {
    if ($eulaIsPlaceholder) { Fail 'A release build needs the owner-approved licence text; the placeholder is not acceptable. Pass -EulaRtf.' }
    if (-not $CertThumbprint) { Fail 'A release build needs a trusted code-signing certificate: pass -CertThumbprint or set BAS_WINDOWS_CERT_THUMBPRINT.' }
    $cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue }
    if (-not $cert) { Fail "Certificate $CertThumbprint was not found in the CurrentUser or LocalMachine store." }
    if ($cert.Subject -match 'DEV signing|NOT TRUSTED') { Fail 'That is a development certificate; a release must use the trusted certificate.' }
}

$root = $scriptDir
Push-Location $root
try {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $OutDir = (Resolve-Path $OutDir).Path
    $AgentExe = (Resolve-Path $AgentExe).Path
    $EulaRtf = (Resolve-Path $EulaRtf).Path
    $msiPath = Join-Path $OutDir $MsiName
    Remove-Item $msiPath, "$msiPath.sha256", (Join-Path $OutDir 'SIGNING-MODE.txt') -ErrorAction SilentlyContinue

    Step 'Restoring the pinned WiX toolchain'
    dotnet tool restore | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'dotnet tool restore failed.' }
    dotnet tool run wix extension add $WixUiExtension | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Could not add $WixUiExtension." }

    if (-not $SkipTests) {
        Step 'Running the custom action tests'
        dotnet test CustomActions.Tests --nologo -v q
        if ($LASTEXITCODE -ne 0) { Fail 'Custom action tests failed.' }
    }

    Step 'Building the custom actions'
    dotnet build CustomActions -c Release --no-incremental --nologo -v q
    if ($LASTEXITCODE -ne 0) { Fail 'Custom action build failed.' }
    $caDll = Join-Path $root 'CustomActions\bin\Release\net472\AudspectCA.CA.dll'
    if (-not (Test-Path $caDll)) { Fail "Packaged custom action not produced: $caDll" }

    Step "Building $MsiName $Version"
    dotnet tool run wix build -arch x64 -ext $WixUiExtension `
        -d "Version=$Version" -d "AgentExe=$AgentExe" -d "CaDll=$caDll" -d "EulaRtf=$EulaRtf" `
        Package.wxs Ui.wxs -o $msiPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $msiPath)) { Fail 'wix build failed.' }

    # ICE38/43/57: per-machine Start Menu shortcut false positives. ICE17: the stock licence page's Print button.
    Step 'Validating the MSI (ICE)'
    dotnet tool run wix msi validate -sice ICE38 -sice ICE43 -sice ICE57 -sice ICE17 $msiPath
    if ($LASTEXITCODE -ne 0) { Fail 'MSI validation failed.' }

    Step 'Checking the MSI structure'
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'tests\Test-MsiStructure.ps1') -Msi $msiPath -CaDll $caDll
    if ($LASTEXITCODE -ne 0) { Fail 'MSI structure checks failed.' }

    $mode = 'unsigned'
    if ($Release -or $DevSign) {
        . (Join-Path $root '..\signing\sign-windows.ps1')
        if ($DevSign) {
            Write-Host '[!] DEV SIGNING: this MSI is signed with a throwaway certificate and is NOT trusted. Lab use only.' -ForegroundColor Yellow
            $dev = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Audspect DEV signing - NOT TRUSTED' `
                -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(30)
            $thumb = $dev.Thumbprint; $stamp = ''; $mode = 'DEV-SIGNED (not trusted)'
        } else {
            $thumb = $CertThumbprint; $stamp = 'http://timestamp.digicert.com'; $mode = 'release-signed'
        }
        Step "Signing the MSI ($mode)"
        $ok = Invoke-AuthenticodeSigning -Path $msiPath -CertThumbprint $thumb -TimestampUrl $stamp `
            -CertStoreLocation $(if (Test-Path "Cert:\CurrentUser\My\$thumb") { 'Cert:\CurrentUser\My' } else { 'Cert:\LocalMachine\My' })
        if (-not $ok) { Fail 'Signing failed.' }
        $sig = Get-AuthenticodeSignature -FilePath $msiPath
        if ($Release -and $sig.Status -ne 'Valid') { Fail "The release signature did not verify as Valid (status: $($sig.Status))." }
        if ($DevSign -and -not $sig.SignerCertificate) { Fail 'Dev signing produced no signature.' }
    } else {
        Write-Host '[!] Unsigned MSI: local development only.' -ForegroundColor Yellow
    }

    Set-Content -Path (Join-Path $OutDir 'SIGNING-MODE.txt') -Value $mode -Encoding ASCII
    $hash = (Get-FileHash -Algorithm SHA256 -Path $msiPath).Hash.ToLower()
    Set-Content -Path "$msiPath.sha256" -Value "$hash  $MsiName" -Encoding ASCII
    Step "Done: $msiPath ($mode)"
    Write-Host "    sha256 $hash"
} finally {
    Pop-Location
}
