# Cobalt Group BFSI reconnaissance-gap shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = technique executed and returned a classifiable result. FAIL = expected data missing. ERROR = unclassifiable. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }

function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-RECON-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

function Get-BfsiSimulatorHost { $h = $env:BFSI_SIMULATOR_HOST; if ($h) { return $h }; return 'localhost' }
function Get-BfsiSimulatorPort { $p = $env:BFSI_SIMULATOR_PORT; if ($p) { return [int]$p }; return 9999 }
function Test-BfsiSimulatorConnectivity {
  $simHost = Get-BfsiSimulatorHost
  $port = Get-BfsiSimulatorPort
  try { $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect($simHost, $port); $tcp.Close(); return $true } catch { return $false }
}
