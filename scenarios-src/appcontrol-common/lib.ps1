# Shared application-control oracle for the Application Control Mastery scenarios.
# Mechanisms: AppLocker (AppIDSvc) and WDAC / App Control for Business (Code Integrity).
# The decision function is pure. Every observation is passed in by the caller.
$ErrorActionPreference = 'SilentlyContinue'
$script:AppCtlTid = [guid]::NewGuid().ToString('N')
$script:AppCtlMarker = "BAS-SIM-APPCTL-$($script:AppCtlTid)"
$script:AppCtlWork = Join-Path $env:TEMP "bas-appctl-$($script:AppCtlTid)"

function Get-AppCtlState {
  $st = @{ Build = [Environment]::OSVersion.Version.Build; AlReadable = $false; AlSvc = $false; Al = @{}; WdReadable = $false; Wd = 'NotConfigured'; WdKernel = 'NotConfigured' }
  try {
    $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $st.AlReadable = $true
    foreach ($rc in @($pol.RuleCollections)) { $st.Al[[string]$rc.RuleCollectionType] = [string]$rc.EnforcementMode }
  } catch {}
  foreach ($t in 'Exe', 'Script', 'Dll', 'Msi', 'Appx') { if (-not $st.Al.ContainsKey($t)) { $st.Al[$t] = 'NotConfigured' } }
  $st.AlSvc = ((Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue).Status -eq 'Running')
  try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $map = @{ 0 = 'NotConfigured'; 1 = 'AuditOnly'; 2 = 'Enabled' }
    $u = [int]@($dg)[0].UsermodeCodeIntegrityPolicyEnforcementStatus
    $k = [int]@($dg)[0].CodeIntegrityPolicyEnforcementStatus
    $st.WdReadable = $true
    $st.Wd = [string]$map[$u]
    $st.WdKernel = [string]$map[$k]
  } catch {}
  return $st
}

# Which mechanisms apply to a collection and are able to enforce right now.
function Get-AppCtlMechanisms {
  param($State, [string]$Collection, [string[]]$Allow)
  $m = @()
  if ($Allow -contains 'applocker') {
    $m += @{ Name = 'applocker'; Available = ($State.AlSvc -and $State.AlReadable); Mode = [string]$State.Al[$Collection] }
  }
  if ($Allow -contains 'wdac') {
    $m += @{ Name = 'wdac'; Available = $State.WdReadable; Mode = [string]$State.Wd }
  }
  return $m
}

function Get-AppCtlEvents {
  param([string]$Mechanism, [string]$Collection, [datetime]$Start, [string]$Needle)
  $isScript = ($Collection -eq 'Script' -or $Collection -eq 'Msi')
  if ($Mechanism -eq 'applocker') {
    if ($isScript) { $log = 'Microsoft-Windows-AppLocker/MSI and Script'; $blk = 8007; $aud = 8006 } else { $log = 'Microsoft-Windows-AppLocker/EXE and DLL'; $blk = 8004; $aud = 8003 }
  } else {
    if ($isScript) { $log = 'Microsoft-Windows-AppLocker/MSI and Script'; $blk = 8029; $aud = 8028 } else { $log = 'Microsoft-Windows-CodeIntegrity/Operational'; $blk = 3077; $aud = 3076 }
  }
  $r = @{ Readable = $true; Block = 0; Audit = 0 }
  try {
    $b = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $blk; StartTime = $Start } -ErrorAction Stop)
    $r.Block = @($b | Where-Object { $_.Message -like "*$Needle*" }).Count
  } catch { if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { $r.Readable = $false } }
  try {
    $a = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $aud; StartTime = $Start } -ErrorAction Stop)
    $r.Audit = @($a | Where-Object { $_.Message -like "*$Needle*" }).Count
  } catch { if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { $r.Readable = $false } }
  return $r
}

# Pure decision. Mechs: @{ Name; Available; Mode; Block; Audit; Readable } per applicable mechanism.
function Resolve-AppCtlOutcome {
  param([string]$Expected, [bool]$Ran, $Mechs, [bool]$BuildOk, [bool]$Constrained = $false)
  $avail = @($Mechs | Where-Object { $_.Available })
  if (-not $BuildOk -or $avail.Count -eq 0) { return @{ Outcome = 'not_applicable'; Reason = 'no applicable enforcement mechanism is available on this host (service stopped, not installed, not readable, or Windows build below the test floor)' } }
  $enabled = @($avail | Where-Object { $_.Mode -eq 'Enabled' })
  $audit = @($avail | Where-Object { $_.Mode -eq 'AuditOnly' })
  $unread = @($enabled | Where-Object { -not $_.Readable })
  if ($Ran) {
    if ($Expected -ne 'blocked') { return @{ Outcome = 'allowed_by_policy'; Reason = 'executed; the contract expects this path to be allowed' } }
    if ($enabled.Count -gt 0) { return @{ Outcome = 'allowed_unexpectedly'; Reason = "executed although $((@($enabled | ForEach-Object { $_.Name }) -join ' and ')) is Enabled for this collection" } }
    if ($audit.Count -gt 0) { return @{ Outcome = 'audited_only'; Reason = "executed; $((@($audit | ForEach-Object { $_.Name }) -join ' and ')) is in audit mode, which records but does not prevent" } }
    return @{ Outcome = 'not_enforced'; Reason = 'executed; no applicable mechanism is enforcing this collection' }
  }
  if ($Expected -eq 'allowed') { return @{ Outcome = 'inconclusive'; Reason = 'not executed although the contract expects it allowed' } }
  if ($Constrained -and $enabled.Count -gt 0) { return @{ Outcome = 'blocked_as_expected'; Reason = "the script ran only in ConstrainedLanguage under enforced $((@($enabled | ForEach-Object { $_.Name }) -join ' and ')) policy; full-language execution was prevented" } }
  if ($enabled.Count -eq 0) { return @{ Outcome = 'inconclusive'; Reason = 'not executed, but no applicable mechanism is Enabled for this collection, so the absence cannot be attributed to application control' } }
  if ($unread.Count -gt 0) { return @{ Outcome = 'inconclusive'; Reason = 'the enforcement event log is unreadable; the block cannot be attributed' } }
  $multi = @($enabled | Where-Object { $_.Block -gt 1 })
  if ($multi.Count -gt 0) { return @{ Outcome = 'inconclusive'; Reason = "not executed; $($multi[0].Name) logged $($multi[0].Block) matching block events (exactly 1 required for attribution)" } }
  $by = @($enabled | Where-Object { $_.Block -eq 1 })
  if ($by.Count -eq 0) { return @{ Outcome = 'inconclusive'; Reason = 'not executed; no matching block event from any Enabled mechanism' } }
  return @{ Outcome = 'blocked_as_expected'; Reason = "not executed; one matching block event from $((@($by | ForEach-Object { $_.Name }) -join ' and '))" }
}

function Test-AppCtlMarker {
  param([string]$Path)
  $t = Get-Content -Path $Path -ErrorAction SilentlyContinue
  return [bool](($t -join "`n") -like "*$($script:AppCtlMarker)*")
}

# Runs a process, kills it after the timeout, never leaves a dialog hanging.
function Invoke-AppCtlProc {
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

# Why a test program could not be built. Under WDAC user-mode enforcement PowerShell often runs in
# ConstrainedLanguage, which blocks Add-Type; that is a side effect of enforcement, not a missing compiler.
function Get-AppCtlCompileReason {
  $mode = [string]$ExecutionContext.SessionState.LanguageMode
  if ($mode -ne 'FullLanguage') { return "PowerShell is running in $mode, which blocks compiling test programs; this is an effect of enforcement, so the test could not run and its result is unknown" }
  return 'the test program could not be compiled on this host (no .NET Framework compiler)'
}

# Compiles a tiny unsigned console program that writes the marker to the file named by its first argument.
function New-AppCtlExe {
  param([string]$Path)
  $src = 'public class BasMain { public static void Main(string[] a) { System.IO.File.WriteAllText(a[0], "' + $script:AppCtlMarker + '"); } }'
  try { Add-Type -TypeDefinition $src -OutputAssembly $Path -OutputType ConsoleApplication -ErrorAction Stop } catch { return $false }
  return (Test-Path $Path)
}

# Builds the unsigned test program in $Dir, runs it once, and returns the attempt result.
function Invoke-AppCtlExeAt {
  param([string]$Dir, [string]$Name, [switch]$MarkOfTheWeb)
  New-Item -ItemType Directory -Path $Dir -Force | Out-Null
  $exe = Join-Path $Dir $Name
  if (-not (New-AppCtlExe -Path $exe)) { return @{ Ran = $false; Exit = -1; Note = 'compile_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  if ($MarkOfTheWeb) { try { Set-Content -Path "$exe`:Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3" -ErrorAction Stop } catch {} }
  $mk = Join-Path $Dir "$Name.marker.txt"
  $p = Invoke-AppCtlProc -File $exe -ArgLine "`"$mk`"" -NoShell
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "started=$($p.Started) timed_out=$($p.TimedOut) location=$((Split-Path $Dir -Leaf))"; NotApplicable = '' }
}

# Builds a minimal local MSI whose only action runs cmd.exe to write the marker file. It registers no product.
function New-AppCtlMsi {
  param([string]$Path, [string]$MarkerPath)
  try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.OpenDatabase($Path, 3)
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $sql = @(
      'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)',
      'CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`)',
      'CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)',
      ('INSERT INTO `Property` (`Property`, `Value`) VALUES (''BASCMD'', ''' + $cmd + ''')'),
      ('INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductCode'', ''{' + [guid]::NewGuid().ToString().ToUpper() + '}'')'),
      'INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductName'', ''BAS SIM'')',
      'INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductVersion'', ''1.0.0'')',
      'INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductLanguage'', ''1033'')',
      'INSERT INTO `Property` (`Property`, `Value`) VALUES (''Manufacturer'', ''BAS SIM'')',
      ('INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES (''RunIt'', 50, ''BASCMD'', ''/c echo ' + $script:AppCtlMarker + '> "' + $MarkerPath + '"'')'),
      'INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES (''RunIt'', '''', 1)'
    )
    foreach ($q in $sql) { $v = $db.OpenView($q); $v.Execute(); $v.Close() }
    $si = $db.SummaryInformation(20)
    $si.Property(2) = 'BAS SIM'
    $si.Property(4) = 'BAS SIM'
    $si.Property(7) = 'Intel;1033'
    $si.Property(9) = ('{' + [guid]::NewGuid().ToString().ToUpper() + '}')
    $si.Property(14) = 200
    $si.Property(15) = 2
    $si.Persist()
    $db.Commit()
    foreach ($o in @($si, $v, $db, $wi)) { if ($o) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($o) } }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  } catch { return $false }
  return (Test-Path $Path)
}

# Runs the attempt block and keeps its returned hashtable separate from anything else it wrote,
# so operator warnings (for example a service that could not be restored) are still printed.
function Invoke-AppCtlAttempt {
  param([scriptblock]$Attempt)
  $out = @(& $Attempt)
  $res = $null
  $script:AppCtlExtra = @()
  foreach ($o in $out) { if ($o -is [hashtable]) { $res = $o } else { $script:AppCtlExtra += [string]$o } }
  if (-not $res) { $res = @{ Ran = $false; Exit = -1; Note = 'attempt_returned_no_result'; NotApplicable = '' } }
  return $res
}

# The SID behind an access-control entry. Names differ by Windows language, SIDs do not.
function Get-AppCtlAceSid {
  param($Ace)
  try { return $Ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return [string]$Ace.IdentityReference }
}

function Invoke-AppCtlTest {
  param(
    [Parameter(Mandatory)][string]$Family,
    [Parameter(Mandatory)][string]$Collection,
    [Parameter(Mandatory)][string]$Needle,
    [Parameter(Mandatory)][scriptblock]$Attempt,
    [string]$Expected = 'blocked',
    [string[]]$Mechanisms = @('applocker', 'wdac'),
    [int]$MinBuild = 17763,
    [string]$Technique = '',
    [string[]]$ExtraCleanup = @(),
    [switch]$Direct
  )
  New-Item -ItemType Directory -Path $script:AppCtlWork -Force | Out-Null
  $state = Get-AppCtlState
  $mechs = @(Get-AppCtlMechanisms -State $state -Collection $Collection -Allow $Mechanisms)
  $buildOk = ($state.Build -ge $MinBuild)
  $script:AppCtlExtra = @()
  $att = @{ Ran = $false; Exit = -1; Note = ''; NotApplicable = ''; Constrained = $false }
  $start = Get-Date
  if ($buildOk -and ($Direct -or @($mechs | Where-Object { $_.Available }).Count -gt 0)) {
    try { $att = Invoke-AppCtlAttempt -Attempt $Attempt } catch { $em = ([string]$_.Exception.Message) -replace '[^A-Za-z0-9 :._-]', ''; if ($em.Length -gt 80) { $em = $em.Substring(0, 80) }; $att = @{ Ran = $false; Exit = -1; Note = "attempt_error:$em"; NotApplicable = '' } }
    Start-Sleep -Milliseconds 800
  }
  if ($att.NotApplicable -and -not $Direct) { $buildOk = $false }
  foreach ($m in $mechs) {
    if ($Direct) { $m.Block = 0; $m.Audit = 0; $m.Readable = $true; continue }
    $ev = Get-AppCtlEvents -Mechanism $m.Name -Collection $Collection -Start $start.AddSeconds(-1) -Needle $Needle
    $m.Block = $ev.Block; $m.Audit = $ev.Audit; $m.Readable = $ev.Readable
  }
  if ($Direct) {
    # Integrity tests observe the denial or the exposure themselves; there is no block event to count.
    $okOut = @('blocked_as_expected', 'allowed_unexpectedly', 'not_enforced', 'audited_only', 'inconclusive', 'not_applicable')
    if (-not $buildOk) { $r = @{ Outcome = 'not_applicable'; Reason = 'the Windows build is below the test floor' } }
    elseif ($att.NotApplicable) { $r = @{ Outcome = 'not_applicable'; Reason = [string]$att.NotApplicable } }
    elseif ($att.Verdict -and ($okOut -contains [string]$att.Verdict.Outcome)) { $r = @{ Outcome = [string]$att.Verdict.Outcome; Reason = [string]$att.Verdict.Reason } }
    else { $r = @{ Outcome = 'inconclusive'; Reason = 'the test did not reach a verdict' } }
  } else {
    $r = Resolve-AppCtlOutcome -Expected $Expected -Ran ([bool]$att.Ran) -Mechs $mechs -BuildOk $buildOk -Constrained ([bool]$att.Constrained)
  }
  Remove-Item -Path $script:AppCtlWork -Recurse -Force -ErrorAction SilentlyContinue
  foreach ($x in $ExtraCleanup) { Remove-Item -Path $x -Recurse -Force -ErrorAction SilentlyContinue }
  $cleanOk = -not (Test-Path $script:AppCtlWork)
  foreach ($x in $ExtraCleanup) { if (Test-Path $x) { $cleanOk = $false } }
  foreach ($x in @($script:AppCtlExtra)) { if ($x) { Write-Output $x } }
  Write-Output "APPCTL_FAMILY: $Family"
  Write-Output "APPCTL_HOST: os_build=$($state.Build) technique=$Technique"
  Write-Output "APPCTL_COVERAGE: applocker_$Collection=$($state.Al[$Collection]) applocker_svc_running=$($state.AlSvc) wdac_umci=$($state.Wd) wdac_readable=$($state.WdReadable)"
  Write-Output "APPCTL_EVIDENCE: test_id=$($script:AppCtlTid) expected=$Expected ran=$([bool]$att.Ran) exit=$($att.Exit) note=$($att.Note) block_events=[$((@($mechs | ForEach-Object { "$($_.Name)=$($_.Block)" })) -join ',')] audit_events=[$((@($mechs | ForEach-Object { "$($_.Name)=$($_.Audit)" })) -join ',')] cleanup_verified=$cleanOk capture=$((Get-Date).ToString('o'))"
  $det = 'unknown'
  try {
    $sy = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $start } -ErrorAction Stop)
    $det = if (@($sy | Where-Object { $_.Message -like "*$($script:AppCtlTid)*" }).Count -gt 0) { 'visible' } else { 'not_visible' }
  } catch {}
  Write-Output "APPCTL_DETECTION: source=sysmon_process_create result=$det"
  Write-Output "APPCTL_OUTCOME: $($r.Outcome)"
  $reason = $r.Reason; if ($att.NotApplicable -and -not $Direct) { $reason = $att.NotApplicable }
  switch ($r.Outcome) {
    'blocked_as_expected'  { Write-Output "PASS: $reason. [BAS-SIM]" }
    'allowed_by_policy'    { Write-Output "PASS: $reason. [BAS-SIM]" }
    'allowed_unexpectedly' { Write-Output "FAIL: $reason. [BAS-SIM]" }
    'not_enforced'         { Write-Output "FAIL: $reason. [BAS-SIM]" }
    'audited_only'         { Write-Output "FAIL: $reason. [BAS-SIM]" }
    default                { Write-Output "SKIP: $reason. [BAS-SIM]" }
  }
}
