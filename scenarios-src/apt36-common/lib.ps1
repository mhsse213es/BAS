# APT36 mastery shared library. ASCII only, no here-strings. Minified into every step by appctlgen.
# Verdict model: PASS only when a block event names this test; a run that did not execute and has no block event is inconclusive.
# Telemetry visibility is reported separately and never changes a prevention verdict.
$script:A36Run = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:A36Extra = @()

function Get-A36Control {
  $r = @{ Build = [Environment]::OSVersion.Version.Build; DefenderReadable = $false; DefenderOn = $false; AsrBlock = 0; AppLocker = 'NotConfigured' }
  try { $s = Get-MpComputerStatus -ErrorAction Stop; $r.DefenderReadable = $true; $r.DefenderOn = ([bool]$s.RealTimeProtectionEnabled -and [bool]$s.AntivirusEnabled) } catch {}
  try { $p = Get-MpPreference -ErrorAction Stop; $r.AsrBlock = @($p.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count } catch {}
  try {
    $svc = Get-Service -Name AppIDSvc -ErrorAction Stop
    if ($svc.Status -eq 'Running') {
      $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop
      foreach ($c in @($pol.RuleCollections)) { if ([string]$c.EnforcementMode -eq 'Enabled') { $r.AppLocker = 'Enabled' } }
    }
  } catch {}
  return $r
}

# Block events that name this test. Defender 1116 (detection) and 1121 (ASR block); AppLocker 8004 (EXE/DLL) and 8007 (MSI/script).
function Get-A36Blocks {
  param([datetime]$Start, [string]$Needle)
  $r = @{ Defender = 0; AppLocker = 0; Readable = $true }
  $q = @(
    @{ Key = 'Defender'; Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116, 1121) },
    @{ Key = 'AppLocker'; Log = 'Microsoft-Windows-AppLocker/EXE and DLL'; Ids = @(8004) },
    @{ Key = 'AppLocker'; Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Ids = @(8007) }
  )
  foreach ($x in $q) {
    try {
      $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $x.Log; Id = $x.Ids; StartTime = $Start } -ErrorAction Stop)
      $r[$x.Key] += @($ev | Where-Object { $_.Message -like "*$Needle*" }).Count
    } catch {
      $f = [string]$_.FullyQualifiedErrorId
      if ($f -like '*NoMatchingEventsFound*' -or $f -like '*NoMatchingLogsFound*') { continue }
      $r.Readable = $false
    }
  }
  return $r
}

function Resolve-A36Outcome {
  param([bool]$Ran, [int]$Blocks, [bool]$Enforcing, [bool]$Readable, [bool]$BuildOk = $true)
  if (-not $BuildOk) { return @{ Outcome = 'not_applicable'; Reason = 'the Windows build is below the supported floor for this test' } }
  if ($Ran) {
    if ($Blocks -gt 0) { return @{ Outcome = 'allowed_unexpectedly'; Reason = 'the behavior executed although a block event naming this test was recorded' } }
    if ($Enforcing) { return @{ Outcome = 'allowed_unexpectedly'; Reason = 'the behavior executed while Microsoft Defender or AppLocker prevention was active' } }
    return @{ Outcome = 'not_enforced'; Reason = 'the behavior executed and no Microsoft Defender or AppLocker prevention was active' }
  }
  if ($Blocks -gt 0) { return @{ Outcome = 'prevented'; Reason = "not executed; $Blocks block event(s) name this test" } }
  if (-not $Readable) { return @{ Outcome = 'inconclusive'; Reason = 'not executed, and a block log was unreadable, so the absence cannot be attributed' } }
  return @{ Outcome = 'inconclusive'; Reason = 'not executed, but no block event names this test, so the absence cannot be attributed to a control' }
}

# Telemetry visibility per spec 'kind:eventid'. visible = an event naming this test exists; not_visible = the log exists and has none; unavailable = the log is absent.
function Get-A36Telemetry {
  param([string[]]$Specs, [datetime]$Start, [string]$Needle)
  $logs = @{ sysmon = 'Microsoft-Windows-Sysmon/Operational'; ps = 'Microsoft-Windows-PowerShell/Operational'; sec = 'Security'; wmi = 'Microsoft-Windows-WMI-Activity/Operational'; task = 'Microsoft-Windows-TaskScheduler/Operational'; sys = 'System'; dns = 'Microsoft-Windows-DNS-Client/Operational' }
  $out = [ordered]@{}
  foreach ($sp in @($Specs)) {
    if (-not $sp) { continue }
    $parts = $sp.Split(':')
    $st = 'unavailable'
    try {
      $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $logs[$parts[0]]; Id = [int]$parts[1]; StartTime = $Start } -ErrorAction Stop)
      $st = if (@($ev | Where-Object { $_.Message -like "*$Needle*" }).Count -gt 0) { 'visible' } else { 'not_visible' }
    } catch { if ([string]$_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { $st = 'not_visible' } }
    $out[$sp] = $st
  }
  return $out
}

function Test-A36Marker {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  return ((Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue) -join ' ') -like "*$($script:A36Marker)*"
}

function Invoke-A36Proc {
  param([string]$File, [string]$ArgLine, [int]$TimeoutSec = 25, [switch]$NoShell)
  $r = @{ Started = $false; Exit = -1; TimedOut = $false }
  try {
    if ($NoShell) {
      $psi = New-Object Diagnostics.ProcessStartInfo
      $psi.FileName = $File; $psi.Arguments = $ArgLine; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
      $p = [Diagnostics.Process]::Start($psi)
    } else {
      $p = Start-Process -FilePath $File -ArgumentList $ArgLine -WindowStyle Hidden -PassThru -ErrorAction Stop
    }
    $r.Started = $true
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { $r.TimedOut = $true; try { $p.Kill() } catch {} } else { $r.Exit = $p.ExitCode }
  } catch {}
  return $r
}

# Runs the attempt and keeps its returned hashtable apart from anything else it wrote, so warnings are still printed.
function Invoke-A36Attempt {
  param([scriptblock]$Attempt)
  $out = @(& $Attempt)
  $res = $null
  $script:A36Extra = @()
  foreach ($o in $out) { if ($o -is [hashtable]) { $res = $o } else { $script:A36Extra += [string]$o } }
  if (-not $res) { $res = @{ Ran = $false; Note = 'attempt_returned_no_result'; NotApplicable = '' } }
  return $res
}

# Mode Prevention (default): outcome from execution plus block evidence.
# Mode Telemetry: the behavior must run and every -Require spec must be visible; says nothing about prevention.
# Mode Direct: the attempt returns Verdict = @{ Outcome; Reason } for posture or configuration checks.
function Invoke-A36Test {
  param(
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$Technique,
    [Parameter(Mandatory)][scriptblock]$Attempt,
    [string]$Mode = 'Prevention',
    [string[]]$Telemetry = @(),
    [string[]]$Require = @(),
    [string[]]$ExtraCleanup = @(),
    [int]$MinBuild = 17763,
    [string]$Summary = '',
    [string]$Needle = ''
  )
  $script:A36Tag = "bas_a36_$($script:A36Run)_$Id"
  $script:A36Work = Join-Path $env:TEMP $script:A36Tag
  $script:A36Marker = "BAS-SIM-APT36-$($script:A36Run)-$Id"
  $needleText = if ($Needle) { $Needle } else { $script:A36Tag }
  New-Item -ItemType Directory -Path $script:A36Work -Force | Out-Null
  $ctl = Get-A36Control
  $buildOk = ($ctl.Build -ge $MinBuild)
  $att = @{ Ran = $false; Note = ''; NotApplicable = '' }
  $start = Get-Date
  if ($buildOk) {
    try { $att = Invoke-A36Attempt -Attempt $Attempt } catch { $em = ([string]$_.Exception.Message) -replace '[^A-Za-z0-9 :._-]', ''; if ($em.Length -gt 80) { $em = $em.Substring(0, 80) }; $att = @{ Ran = $false; Note = "attempt_error:$em"; NotApplicable = '' } }
    Start-Sleep -Milliseconds 800
  }
  $enforcing = ($ctl.DefenderOn -or $ctl.AsrBlock -gt 0 -or $ctl.AppLocker -eq 'Enabled')
  $blocks = @{ Defender = 0; AppLocker = 0; Readable = $true }
  if ($Mode -eq 'Prevention' -and $buildOk) { $blocks = Get-A36Blocks -Start $start.AddSeconds(-1) -Needle $needleText }
  $specs = @($Telemetry) + @($Require) | Where-Object { $_ } | Select-Object -Unique
  $tele = [ordered]@{}
  if ($buildOk -and $specs.Count -gt 0) { $tele = Get-A36Telemetry -Specs $specs -Start $start.AddSeconds(-1) -Needle $needleText }
  if (-not $buildOk) { $r = @{ Outcome = 'not_applicable'; Reason = 'the Windows build is below the supported floor for this test' } }
  elseif ($att.NotApplicable) { $r = @{ Outcome = 'not_applicable'; Reason = [string]$att.NotApplicable } }
  elseif ($Mode -eq 'Direct') {
    $ok = @('prevented', 'allowed_unexpectedly', 'not_enforced', 'inconclusive', 'not_applicable', 'telemetry_visible', 'telemetry_not_visible')
    if ($att.Verdict -and ($ok -contains [string]$att.Verdict.Outcome)) { $r = @{ Outcome = [string]$att.Verdict.Outcome; Reason = [string]$att.Verdict.Reason } }
    else { $r = @{ Outcome = 'inconclusive'; Reason = 'the test did not reach a verdict' } }
  }
  elseif ($Mode -eq 'Telemetry') {
    if (-not $att.Ran) { $r = @{ Outcome = 'inconclusive'; Reason = 'the behavior did not run, so its telemetry cannot be judged' } }
    else {
      $st = @($Require | ForEach-Object { $tele[$_] })
      if (@($st | Where-Object { $_ -eq 'unavailable' }).Count -gt 0) { $r = @{ Outcome = 'inconclusive'; Reason = 'a required log is not available on this host, so visibility cannot be judged' } }
      elseif (@($st | Where-Object { $_ -ne 'visible' }).Count -gt 0) { $r = @{ Outcome = 'telemetry_not_visible'; Reason = 'the behavior ran but the required host telemetry did not record it' } }
      else { $r = @{ Outcome = 'telemetry_visible'; Reason = 'the behavior ran and the required host telemetry recorded it; forwarding to a SIEM is not verified' } }
    }
  }
  else { $r = Resolve-A36Outcome -Ran ([bool]$att.Ran) -Blocks ([int]($blocks.Defender + $blocks.AppLocker)) -Enforcing $enforcing -Readable ([bool]$blocks.Readable) -BuildOk $buildOk }
  Remove-Item -LiteralPath $script:A36Work -Recurse -Force -ErrorAction SilentlyContinue
  foreach ($x in $ExtraCleanup) { Remove-Item -LiteralPath $x -Recurse -Force -ErrorAction SilentlyContinue }
  $cleanOk = -not (Test-Path -LiteralPath $script:A36Work)
  foreach ($x in $ExtraCleanup) { if (Test-Path -LiteralPath $x) { $cleanOk = $false } }
  if ($att.ContainsKey('CleanupOk') -and -not [bool]$att.CleanupOk) { $cleanOk = $false }
  foreach ($x in @($script:A36Extra)) { if ($x) { Write-Output $x } }
  Write-Output "EXEC $($Technique): $Summary ran=$([bool]$att.Ran). [BAS-SIM-APT36-$Id]"
  Write-Output "APT36_FAMILY: $Id"
  Write-Output "APT36_HOST: os_build=$($ctl.Build) technique=$Technique mode=$Mode"
  Write-Output "APT36_CONTROL: defender_on=$($ctl.DefenderOn) defender_readable=$($ctl.DefenderReadable) asr_block_rules=$($ctl.AsrBlock) applocker=$($ctl.AppLocker)"
  Write-Output "APT36_EVIDENCE: run=$($script:A36Run) tag=$($script:A36Tag) ran=$([bool]$att.Ran) note=$($att.Note) block_events=[defender=$($blocks.Defender) applocker=$($blocks.AppLocker)] cleanup_verified=$cleanOk capture=$((Get-Date).ToString('o'))"
  Write-Output "APT36_TELEMETRY: $((@($tele.GetEnumerator() | ForEach-Object { ($_.Key -replace ':', '_') + '=' + $_.Value }) -join ' '))"
  Write-Output "APT36_OUTCOME: $($r.Outcome)"
  $v = 'SKIP'
  if (@('prevented', 'telemetry_visible') -contains $r.Outcome) { $v = 'PASS' }
  elseif (@('allowed_unexpectedly', 'not_enforced', 'telemetry_not_visible') -contains $r.Outcome) { $v = 'FAIL' }
  Write-Output "$($v): $($r.Reason). [BAS-SIM-APT36-$Id]"
}

# Shared safety helpers for gated steps. A gate must be exactly 'true' (case-sensitive); the admin check is separate.
function Test-A36Gate {
  param([string]$Name)
  return ([string](Get-Item -Path ('env:' + $Name) -ErrorAction SilentlyContinue).Value -ceq 'true')
}
function Test-A36Admin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
