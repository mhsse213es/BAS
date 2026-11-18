# Cobalt Group BFSI persistence-variants shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = technique succeeded on this unenforced host (real result, not simulated). FAIL = blocked. ERROR = unclassifiable. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:CgTag = 'BAS-SIM-pers-' + $script:CgRun

function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-PERS-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

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

function New-CgTestAccountName { param([string]$Suffix)
  $name = 'bas-pers-' + $script:CgRun + '-' + $Suffix
  if ($name.Length -gt 20) { $name = $name.Substring(0, 20) }
  return $name
}

function Test-CgRunKeyExists { param([string]$Name)
  $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
  $v = (Get-ItemProperty -Path $p -Name $Name -ErrorAction SilentlyContinue)
  return ($v -ne $null)
}

function Test-CgWmiSubscriptionExists { param([string]$Tag)
  $filter = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -Filter "Name='$Tag-filter'" -ErrorAction SilentlyContinue
  $consumer = Get-WmiObject -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Filter "Name='$Tag-consumer'" -ErrorAction SilentlyContinue
  $binding = Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -ErrorAction SilentlyContinue | Where-Object { $_.Filter -like "*$Tag-filter*" }
  return @{ Filter = ($filter -ne $null); Consumer = ($consumer -ne $null); Binding = ($binding -ne $null) }
}
