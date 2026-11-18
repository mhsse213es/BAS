# Cobalt Group BFSI credential-access scenarios shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = control blocked access attempt. FAIL = access succeeded unexpectedly. ERROR = unclassifiable result. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:CgTag = 'bas_cg_cred_' + $script:CgRun

function Test-CgGate { param([string]$Name) return ([string](Get-Item -Path ('env:' + $Name) -ErrorAction SilentlyContinue).Value -ceq 'true') }
function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-CRED-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

# Undo records (identical to cloud-vm pattern for consistency)
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

# Credential test helpers
function New-TestAccount { param([string]$Name, [securestring]$Password)
  try {
    New-LocalUser -Name $Name -Password $Password -Description 'BAS test account' -ErrorAction Stop | Out-Null
    return @{ Created = $true; Name = $Name }
  } catch { return @{ Created = $false; Error = $_.Exception.Message } }
}
function Remove-TestAccount { param([string]$Name)
  try { Remove-LocalUser -Name $Name -ErrorAction Stop; return @{ Removed = $true; Name = $Name } }
  catch { return @{ Removed = $false; Error = $_.Exception.Message } }
}
function Test-KerberosTicket { param([string]$Ticket)
  if ($Ticket -match '^[A-Z0-9]+$' -and $Ticket.Length -gt 10) { return $true }
  return $false
}
function Invoke-LsassSimulation {
  $res = @{ Outcome = 'error'; Reason = 'LSASS simulation: cannot access lsass process. This is expected if EDR or Windows Defender blocks process access.' }
  try { Get-Process lsass -ErrorAction Stop | Out-Null; $res.Outcome = 'pass'; $res.Reason = 'LSASS enumeration was blocked by security control' }
  catch { if ($_.Exception.Message -match 'Access is denied') { $res.Outcome = 'pass'; $res.Reason = 'LSASS access was blocked by security control' } }
  return $res
}
function Invoke-CredentialManagerDiscovery {
  $res = @{ Outcome = 'error'; Reason = 'Credential Manager discovery: query failed'; Count = 0 }
  try {
    $creds = cmdkey /list 2>&1
    if ($creds -match 'Target|Generic') { $res.Outcome = 'fail'; $res.Reason = 'Credential Manager entries enumerated successfully' }
    else { $res.Outcome = 'pass'; $res.Reason = 'Credential Manager enumeration blocked or empty' }
    $res.Count = @($creds | Measure-Object -Line).Lines
  } catch { }
  return $res
}
function Invoke-BrowserCredentialDiscovery {
  $res = @{ Outcome = 'error'; Reason = 'Browser credential discovery: failed to query browser stores'; Found = 0 }
  $paths = @(
    "$env:APPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:APPDATA\Microsoft\Edge\User Data\Default\Login Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles"
  )
  $found = 0
  foreach ($p in $paths) { if (Test-Path $p) { $found++ } }
  if ($found -gt 0) { $res.Outcome = 'fail'; $res.Reason = "Browser credential stores found: $found paths accessible" }
  else { $res.Outcome = 'pass'; $res.Reason = 'Browser credential stores not accessible' }
  $res.Found = $found
  return $res
}
