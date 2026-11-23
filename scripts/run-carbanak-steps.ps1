<#
.SYNOPSIS
  Runs selected steps of a Carbanak scenario file on a Windows lab endpoint and prints the raw output.

.DESCRIPTION
  Pulls each step's `command` block out of the scenario YAML and runs it in its own PowerShell process.
  Steps run in the order given, in one session, so Stage 8 steps share the run state file that 8a writes.
  The script prints evidence only. The fraud and endpoint verdicts are scored by the orchestrator from the
  EXEC lines and BAS-FRAUD-CONTROL markers printed here.

.PARAMETER Scenario
  Scenario file name, relative to the repo's scenarios folder.

.PARAMETER StepPrefix
  Step name prefixes to run, in order. Each must match the start of a step's name, e.g. 'Carbanak Stage 8a '.

.PARAMETER DryRun
  Extract and report each command's size without running anything.

.EXAMPLE
  .\scripts\run-carbanak-steps.ps1 -Scenario carbanak-kill-chain.yaml -StepPrefix 'Carbanak Stage 8a ','Carbanak Stage 8b '
#>
param(
  [string]$Scenario = 'carbanak-kill-chain.yaml',
  [string[]]$StepPrefix = @('Carbanak Stage 8a ', 'Carbanak Stage 8b ', 'Carbanak Stage 8c ', 'Carbanak Stage 8d ', 'Carbanak Stage 8e ', 'Carbanak Stage 8f ', 'Carbanak Stage 8g '),
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$file = Join-Path $repo (Join-Path 'scenarios' $Scenario)
if (-not (Test-Path -LiteralPath $file)) { throw "scenario not found: $file" }
$lines = Get-Content -LiteralPath $file -Encoding UTF8

function Get-StepCommand([string[]]$Lines, [string]$Prefix) {
  $start = -1
  for ($i = 0; $i -lt $Lines.Count; $i++) {
    if ($Lines[$i] -match ('^  - name: "' + [regex]::Escape($Prefix))) { $start = $i; break }
  }
  if ($start -lt 0) { throw "step not found in ${Scenario}: '$Prefix'" }
  $cmd = -1
  for ($j = $start + 1; $j -lt $Lines.Count; $j++) {
    if ($Lines[$j] -match '^  - name: ') { throw "step '$Prefix' has no command block before the next step" }
    if ($Lines[$j] -match '^    command: \|\s*$') { $cmd = $j; break }
  }
  if ($cmd -lt 0) { throw "step '$Prefix' has no command block" }
  $out = New-Object System.Collections.Generic.List[string]
  for ($k = $cmd + 1; $k -lt $Lines.Count; $k++) {
    $l = $Lines[$k]
    if ($l -match '^      ') { $out.Add($l.Substring(6)) }
    elseif ($l.Trim() -eq '') { $out.Add('') }
    else { break }
  }
  return ($out -join "`r`n")
}

$results = @()
foreach ($p in $StepPrefix) {
  $cmd = Get-StepCommand $lines $p
  if ($DryRun) {
    Write-Output ("DRY RUN: '{0}' -> {1} characters extracted" -f $p.Trim(), $cmd.Length)
    continue
  }
  $tmp = Join-Path $env:TEMP ('bas_step_' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
  try {
    Set-Content -LiteralPath $tmp -Value $cmd -Encoding UTF8
    Write-Output ('==== ' + $p.Trim())
    # The step's stderr is evidence, not a runner failure. Under 'Stop', a native command's stderr
    # would end this runner, so relax the preference for the child call only.
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
      $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1 | ForEach-Object { "$_" }
    } finally {
      $ErrorActionPreference = $prevPref
    }
    $out | ForEach-Object { Write-Output $_ }
    $results += [pscustomobject]@{ Step = $p.Trim(); Output = ($out -join "`n") }
  } finally {
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
  }
}

if (-not $DryRun) {
  Write-Output ''
  Write-Output '==== evidence summary (raw; verdicts are scored by the orchestrator)'
  foreach ($r in $results) {
    $exec = ($r.Output -split "`n" | Where-Object { $_ -match '^EXEC |^SKIP:|^REFUSED:' }) -join ' | '
    $fraud = ($r.Output -split "`n" | Where-Object { $_ -match 'BAS-FRAUD-CONTROL' }) -join ' | '
    Write-Output ("{0}`n   result : {1}`n   fraud  : {2}" -f $r.Step, $exec, $fraud)
  }
}
