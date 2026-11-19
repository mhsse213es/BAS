# Cobalt Group BFSI defense-evasion scenarios shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = control blocked/detected the action. FAIL = action succeeded unexpectedly. ERROR = unclassifiable. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:CgTag = 'bas_sim_eva_' + $script:CgRun

function Test-CgGate { param([string]$Name) return ([string](Get-Item -Path ('env:' + $Name) -ErrorAction SilentlyContinue).Value -ceq 'true') }
function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-EVA-' + $Id + ']')
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
function Set-CgUndoRecord { param([string]$Id, $Data)
  [IO.File]::WriteAllText((Get-CgUndoPath $Id), ($Data | ConvertTo-Json -Depth 6 -Compress), [Text.Encoding]::ASCII)
}
function Read-CgUndoRecord { param([string]$Id)
  $p = Get-CgUndoPath $Id
  if (-not (Test-Path -LiteralPath $p)) { return $null }
  try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { return 'unreadable' }
}
function Remove-CgUndoRecord { param([string]$Id) Remove-Item -LiteralPath (Get-CgUndoPath $Id) -Force -ErrorAction SilentlyContinue }

# Defense-evasion helpers
function Invoke-EncodedCommandProbe { param([string]$PlainText, [string]$ExpectMarker)
  $res = @{ Outcome = 'error'; Reason = 'Encoded-command probe failed to run'; Ran = $false }
  try {
    $bytes = [Text.Encoding]::Unicode.GetBytes($PlainText)
    $encoded = [Convert]::ToBase64String($bytes)
    $out = powershell -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1
    if ("$out" -match [regex]::Escape($ExpectMarker)) { $res.Ran = $true; $res.Outcome = 'fail'; $res.Reason = 'Encoded PowerShell command executed without being blocked or flagged' }
    else { $res.Outcome = 'pass'; $res.Reason = 'Encoded PowerShell command was blocked or did not produce the expected marker' }
  } catch {}
  return $res
}
