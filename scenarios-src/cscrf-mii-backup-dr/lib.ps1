# CSCRF-MII backup pack shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = configured as expected. FAIL = gap observed. ERROR = check could not run. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-BDR-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }
function Test-CgBackupGate { return ($env:BAS_CONFIRM_BACKUP_TEST -eq 'true') }
function Get-CgLatestBackupTime {
  $out = (& wbadmin.exe get versions 2>&1) -join "`n"
  if ($out -match 'No backup was found') { return 'none' }
  $m = [regex]::Matches($out, 'Backup time:\s*(.+)')
  if ($m.Count -eq 0) { return $null }
  $latest = $null
  foreach ($x in $m) { $t = $null; if ([datetime]::TryParse($x.Groups[1].Value.Trim(), [ref]$t) -and ($latest -eq $null -or $t -gt $latest)) { $latest = $t } }
  return $latest
}
function Get-CgDrTcp { param([string]$Ip, [int]$Port, [int]$TimeoutMs = 3000)
  $c = New-Object System.Net.Sockets.TcpClient
  try { $ar = $c.BeginConnect($Ip, $Port, $null, $null); if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $c.Connected) { return 'open' }; return 'closed' } catch { return 'closed' } finally { $c.Close() }
}
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
