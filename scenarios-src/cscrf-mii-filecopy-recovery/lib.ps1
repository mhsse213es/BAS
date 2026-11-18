# CSCRF-MII file-copy pack shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = configured as expected. FAIL = gap observed. ERROR = check could not run. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-FC-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }
function Test-CgFcGate { return ($env:BAS_CONFIRM_FC_TEST -eq 'true') }
function Get-CgSha256 { param([string]$Path) return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
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
