Invoke-AppCtlTest -Family 'policy_after_reboot' -Collection 'Exe' -Needle 'CodeIntegrity' -Technique 'T1562.001' -Direct -Attempt {
  $st = Get-AppCtlState
  $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
  $svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" -ErrorAction SilentlyContinue
  $startMode = if ($svc) { [string]$svc.StartMode } else { 'absent' }
  $alPersisted = ($st.AlReadable -and (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'))
  $dir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
  $wdFile = ((Test-Path $dir) -and @(Get-ChildItem -Path $dir -Filter *.cip -ErrorAction SilentlyContinue).Count -gt 0) -or (Test-Path (Join-Path $env:SystemRoot 'System32\CodeIntegrity\SiPolicy.p7b'))
  $load = 0; $logOk = $true
  try { $load = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3099; StartTime = $boot } -ErrorAction Stop).Count } catch { if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { $logOk = $false } }
  $note = "last_boot=$(if ($boot) { $boot.ToString('o') } else { 'unknown' }) appid_start_mode=$startMode applocker_policy_in_registry=$alPersisted wdac_policy_file_on_disk=$wdFile policy_load_events_since_boot=$load log_readable=$logOk. No reboot is performed; this reads whether enforcement is configured to survive one."
  $enforcing = ($st.Al.Values -contains 'Enabled') -or ($st.Wd -eq 'Enabled')
  if (-not $enforcing) { return @{ NotApplicable = 'no application control policy is enforcing on this host, so there is no enforcement whose persistence can be shown'; Note = $note } }
  $alOk = (-not ($st.Al.Values -contains 'Enabled')) -or ($alPersisted -and $startMode -in 'Auto', 'Automatic', 'Manual' -and $startMode -ne 'Disabled')
  $wdOk = ($st.Wd -ne 'Enabled') -or ($wdFile -and ($load -gt 0 -or -not $logOk))
  if ($alOk -and $wdOk -and $logOk) { return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'enforcing policy is stored persistently and was loaded after the last boot' }; Note = $note } }
  if (-not $logOk) { return @{ Verdict = @{ Outcome = 'inconclusive'; Reason = 'the Code Integrity log is unreadable, so the post-boot policy load cannot be confirmed' }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'not_enforced'; Reason = 'enforcement is active now but is not shown to be stored persistently or loaded at boot; it may not survive a reboot' }; Note = $note }
}
