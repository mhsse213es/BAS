# Builds bas-pshost.exe from bas-pshost.cs with the .NET Framework compiler
# that ships with Windows. Nothing is downloaded.
#
#   powershell -ExecutionPolicy Bypass -File tools\inprocess-host\build.ps1 -OutDir <dir>
param(
    [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc.exe not found at $csc" }
$src = Join-Path $PSScriptRoot 'bas-pshost.cs'
$out = Join-Path $OutDir 'bas-pshost.exe'
# The PowerShell automation assembly lives in the GAC. Resolve its path, since
# csc cannot always find it by simple name.
$sma = Get-ChildItem -Path (Join-Path $env:SystemRoot 'Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation') -Filter 'System.Management.Automation.dll' -Recurse -ErrorAction Stop | Select-Object -First 1
if (-not $sma) { throw 'System.Management.Automation.dll not found in the GAC' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
& $csc /nologo /target:exe /platform:anycpu "/reference:$($sma.FullName)" "/out:$out" $src
if ($LASTEXITCODE -ne 0) { throw "csc failed with exit $LASTEXITCODE" }
Write-Output "Built $out"
