# CSCRF-MII endpoint audit pack shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = control behaves as expected. FAIL = control gap observed. ERROR = check could not run. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:ProcessCreationGuid = '{0CCE922B-69AE-11D9-BED3-505054503030}'

function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-EA-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

function Test-CgEndpointGate { return ($env:BAS_CONFIRM_ENDPOINT_CHANGE -eq 'true') }

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

# Returns the Process Creation audit setting as 0 (No Auditing), 1 (Success), 2 (Failure), 3 (Success and Failure), or $null if unreadable.
# Reads the GUID form so the subcategory name is not locale dependent. The setting text is English on this host.
function Get-CgProcessCreationSetting {
  $csv = & auditpol.exe /get /subcategory:$script:ProcessCreationGuid /r 2>$null
  $row = @($csv | ConvertFrom-Csv)
  if ($row.Count -eq 0) { return $null }
  switch ([string]$row[0].'Inclusion Setting') {
    'No Auditing' { return 0 }
    'Success' { return 1 }
    'Failure' { return 2 }
    'Success and Failure' { return 3 }
    default { return $null }
  }
}
