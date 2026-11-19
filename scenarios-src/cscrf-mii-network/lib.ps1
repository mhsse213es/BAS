# CSCRF-MII network pack shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = control behaves as expected. FAIL = control gap observed. ERROR = check could not run. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }

function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-NET-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

function Test-CgPrivateIPv4 { param([string]$Ip)
  $addr = $null
  if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $false }
  if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
  $b = $addr.GetAddressBytes()
  return ($b[0] -eq 10) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)
}

# Attempts one TCP connection. Returns 'open', 'closed' or 'error'. Never throws.
function Test-CgTcpPort { param([string]$Ip, [int]$Port, [int]$TimeoutMs = 1500)
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $c.BeginConnect($Ip, $Port, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $c.Connected) { $c.EndConnect($ar); return 'open' }
    return 'closed'
  } catch { return 'closed' } finally { $c.Close() }
}
