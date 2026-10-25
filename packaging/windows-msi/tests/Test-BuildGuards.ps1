#requires -Version 5.1
<#
  The release guards in build-msi.ps1 must stop the build before anything is produced.
  These run the real script with inputs a release must refuse. Nothing is built or signed.
#>
$ErrorActionPreference = 'Stop'
$build = Join-Path $PSScriptRoot '..\build-msi.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("audspect-guards-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$fakeExe = Join-Path $tmp 'bas_agent.exe'; Set-Content $fakeExe 'x'
$realEula = Join-Path $tmp 'eula.rtf'; Set-Content $realEula '{\rtf1 owner approved text}'
$placeholder = Join-Path $PSScriptRoot '..\eula.placeholder.rtf'
$failures = 0
$env:BAS_WINDOWS_CERT_THUMBPRINT = ''  # a guard test must not pick up the machine's real certificate

function Expect-Refusal([string]$name, [string[]]$extra, [string]$mustSay) {
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $build -AgentExe $fakeExe -Version 2.1.0 -OutDir (Join-Path $tmp 'out') @extra 2>&1 | Out-String
    $code = $LASTEXITCODE
    $produced = Test-Path (Join-Path $tmp 'out\AudspectAgent-x64.msi')
    if ($code -ne 0 -and $out -match $mustSay -and -not $produced) { Write-Host "PASS  $name" }
    else { Write-Host "FAIL  $name (exit $code, produced=$produced): $out"; $script:failures++ }
}

Expect-Refusal 'release refuses the placeholder licence' @('-Release', '-EulaRtf', $placeholder, '-CertThumbprint', 'ABCDEF') 'placeholder'
Expect-Refusal 'release refuses a missing certificate' @('-Release', '-EulaRtf', $realEula) 'trusted code-signing certificate'
Expect-Refusal 'release refuses an unknown certificate' @('-Release', '-EulaRtf', $realEula, '-CertThumbprint', '0000000000000000000000000000000000000000') 'not found'
Expect-Refusal 'release and dev signing cannot be combined' @('-Release', '-DevSign', '-EulaRtf', $realEula) 'mutually exclusive'

$bad = & powershell -NoProfile -ExecutionPolicy Bypass -File $build -AgentExe $fakeExe -Version 'abc' 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -and $bad -match 'Version') { Write-Host 'PASS  a malformed version is refused' } else { Write-Host 'FAIL  a malformed version is refused'; $failures++ }

Remove-Item -Recurse -Force $tmp
if ($failures) { Write-Host "`n$failures guard check(s) failed"; exit 1 }
Write-Host "`nAll build guards hold."
