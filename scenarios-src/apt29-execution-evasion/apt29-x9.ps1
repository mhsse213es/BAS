Invoke-A29Test -Id 'x9' -Technique 'T1562.002' -Mode Telemetry -Needle 'BASSIM_APT29' -Require @('sys:104') -Telemetry @('sysmon:1') -Summary 'a controlled clear of a dedicated test event log; no real log is touched (T1562.002, T1685.001 in ATT&CK v20)' -Attempt {
  if ($env:BAS_CONFIRM_APT29_TEST_LOG -cne 'true') { return @{ Ran = $false; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APT29_TEST_LOG is not set to true; this step creates and removes a dedicated test event log and is skipped without it' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Note = 'not_admin'; NotApplicable = 'creating an event log needs an administrator identity' } }
  # A fixed name: the Event Log service keeps the log file open until it restarts, so a per-run name would leave one orphan file per run.
  $log = 'BASSIM_APT29'
  $created = $false; $wrote = $false; $cleared = $false; $removed = $false
  try {
    New-EventLog -LogName $log -Source $log -ErrorAction Stop
    $created = $true
    Write-EventLog -LogName $log -Source $log -EventId 1 -Message ('BAS-SIM test entry ' + $script:A29Marker) -ErrorAction Stop
    $wrote = $true
    Clear-EventLog -LogName $log -ErrorAction Stop
    $cleared = $true
  } catch {} finally {
    try { Remove-EventLog -LogName $log -ErrorAction Stop; $removed = $true } catch { $removed = -not [bool](Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue) }
  }
  Start-Sleep -Milliseconds 800
  $residual = Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\winevt\Logs\BASSIM_APT29.evtx')
  return @{ Ran = $cleared; Note = "test_log_created=$created entry_written=$wrote test_log_cleared=$cleared test_log_unregistered=$removed residual_evtx_file_until_eventlog_restart=$residual target=dedicated_test_log_only"; CleanupOk = $removed; NotApplicable = '' }
}
