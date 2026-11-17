Invoke-AppCtlTest -Family 'policy_service_interruption' -Collection 'Exe' -Needle 'AppIDSvc' -Technique 'T1562.001' -Direct -Attempt {
  $svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
  if (-not $svc) { return @{ NotApplicable = 'the AppLocker identity service (AppIDSvc) is not present on this host'; Note = 'no_service' } }
  $sddl = (& (Join-Path $env:SystemRoot 'System32\sc.exe') sdshow AppIDSvc 2>&1 | Where-Object { $_ -match '^D:' }) -join ''
  $stopRight = 0x20
  $weak = @(); $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  try {
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
    foreach ($ace in $sd.DiscretionaryAcl) {
      if ($ace.AceType -ne 'AccessAllowed') { continue }
      $sid = $ace.SecurityIdentifier.Value
      $isPriv = ($sid -in 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
      if (-not $isPriv -and (($ace.AccessMask -band $stopRight) -ne 0)) { $weak += $sid }
    }
  } catch { return @{ Verdict = @{ Outcome = 'inconclusive'; Reason = 'the AppIDSvc security descriptor could not be parsed' }; Note = 'sddl_unparsed' } }
  $liveNote = 'live_stop_not_attempted'
  $stopped = $false
  if ($env:BAS_CONFIRM_APPCONTROL_SERVICE_STOP -ceq 'true') {
    if (-not $isAdmin) { $liveNote = 'live_stop_skipped_not_admin' } else {
      $was = $svc.Status
      Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 800
      $stopped = ((Get-Service -Name AppIDSvc).Status -eq 'Stopped')
      if ($was -eq 'Running') { Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 800 }
      $restored = ((Get-Service -Name AppIDSvc).Status -eq $was)
      $liveNote = "live_stop_attempted stopped=$stopped restored=$restored"
      if (-not $restored) { Write-Output "WARNING: AppIDSvc was not restored to its prior state ($was); start it manually. [BAS-SIM]" }
    }
  }
  $note = "service_status=$($svc.Status) start_type=$((Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" -ErrorAction SilentlyContinue).StartMode) non_admin_stop_rights=$($weak.Count) identity_is_admin=$isAdmin $liveNote"
  if ($weak.Count -gt 0) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = "non-administrative principals hold the stop right on AppIDSvc ($($weak -join ','))" }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'only SYSTEM and administrators can stop the application control service; no unprivileged stop right found' }; Note = $note }
}
