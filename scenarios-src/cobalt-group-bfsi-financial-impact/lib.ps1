# Cobalt Group BFSI financial-impact scenarios shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = control blocked/detected the manipulation. FAIL = manipulation succeeded unexpectedly. ERROR = unclassifiable. SKIP = prerequisite unmet (simulator not running).
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:CgTag = 'bas_sim_fin_' + $script:CgRun
$script:FinTxLimit = 50000

function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-FIN-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

# Undo records (identical pattern to the P0/P1 packs)
function Get-CgUndoPath { param([string]$Id) return (Join-Path $env:TEMP ('bas-cg-undo\' + $Id + '.json')) }
function New-CgUndoRecord { param([string]$Id, $Data)
  $p = Get-CgUndoPath $Id
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
  $fs = [IO.File]::Open($p, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
  try { $b = [Text.Encoding]::ASCII.GetBytes(($Data | ConvertTo-Json -Depth 6 -Compress)); $fs.Write($b, 0, $b.Length) } finally { $fs.Close() }
}
function Read-CgUndoRecord { param([string]$Id)
  $p = Get-CgUndoPath $Id
  if (-not (Test-Path -LiteralPath $p)) { return $null }
  try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { return 'unreadable' }
}
function Remove-CgUndoRecord { param([string]$Id) Remove-Item -LiteralPath (Get-CgUndoPath $Id) -Force -ErrorAction SilentlyContinue }

# Ledger / simulator helpers (same env vars as the P0 discovery pack, so one simulator serves both)
function Get-BfsiSimulatorHost { $h = $env:BFSI_SIMULATOR_HOST; if ($h) { return $h }; return 'localhost' }
function Get-BfsiSimulatorPort { $p = $env:BFSI_SIMULATOR_PORT; if ($p) { return [int]$p }; return 9999 }
function Test-BfsiSimulatorConnectivity {
  $simHost = Get-BfsiSimulatorHost
  $port = Get-BfsiSimulatorPort
  try { $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect($simHost, $port); $tcp.Close(); return $true } catch { return $false }
}
function New-CgLedgerTransaction { param([string]$Id, [double]$Amount, [string]$Account)
  $simHost = Get-BfsiSimulatorHost
  $port = Get-BfsiSimulatorPort
  $res = @{ Code = 0; Error = '' }
  try {
    $body = @{ id = $Id; amount = $Amount; account = $Account } | ConvertTo-Json -Compress
    $uri = "http://${simHost}:${port}/api/ledger/transactions"
    $r = Invoke-WebRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json' -TimeoutSec 5 -ErrorAction Stop
    $res.Code = [int]$r.StatusCode
  } catch {
    try { $res.Code = [int]$_.Exception.Response.StatusCode } catch {}
    $res.Error = $_.Exception.Message
  }
  return $res
}
function Remove-CgLedgerTransaction { param([string]$Id)
  $simHost = Get-BfsiSimulatorHost
  $port = Get-BfsiSimulatorPort
  try { Invoke-WebRequest -Method DELETE -Uri ("http://${simHost}:${port}/api/ledger/transactions/" + $Id) -TimeoutSec 5 -ErrorAction Stop | Out-Null } catch {}
}
function Get-CgLedgerTransactions {
  $simHost = Get-BfsiSimulatorHost
  $port = Get-BfsiSimulatorPort
  $res = @{ Code = 0; List = @() }
  try {
    $r = Invoke-RestMethod -Method GET -Uri ("http://${simHost}:${port}/api/ledger/transactions") -TimeoutSec 5 -ErrorAction Stop
    $res.Code = 200
    $res.List = @($r)
  } catch { try { $res.Code = [int]$_.Exception.Response.StatusCode } catch {} }
  return $res
}
function Invoke-CgLedgerReconcile { param([double]$ExpectedTotal)
  $simHost = Get-BfsiSimulatorHost
  $port = Get-BfsiSimulatorPort
  $res = @{ Code = 0; Balanced = $false; ActualTotal = 0.0 }
  try {
    $body = @{ expectedTotal = $ExpectedTotal } | ConvertTo-Json -Compress
    $r = Invoke-RestMethod -Method POST -Uri ("http://${simHost}:${port}/api/ledger/reconcile") -Body $body -ContentType 'application/json' -TimeoutSec 5 -ErrorAction Stop
    $res.Code = 200
    $res.Balanced = [bool]$r.balanced
    $res.ActualTotal = [double]$r.actualTotal
  } catch { try { $res.Code = [int]$_.Exception.Response.StatusCode } catch {} }
  return $res
}
