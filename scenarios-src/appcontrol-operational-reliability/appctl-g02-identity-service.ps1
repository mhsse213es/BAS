Invoke-AppCtlTest -Family 'identity_service_reliability' -Collection 'Exe' -Needle 'AppIDSvc' -Technique 'T1562.001' -Direct -Attempt {
  $st = Get-AppCtlState
  $enf = @('Exe', 'Script', 'Dll', 'Msi' | Where-Object { $st.Al[$_] -eq 'Enabled' })
  $svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" -ErrorAction SilentlyContinue
  $mode = if ($svc) { [string]$svc.StartMode } else { 'absent' }
  $state = if ($svc) { [string]$svc.State } else { 'absent' }
  $note = "enforced_collections=$($enf -join ',') service_start_mode=$mode service_state=$state"
  if ($enf.Count -eq 0) { return @{ NotApplicable = 'no AppLocker collection is enforced, so the identity service is not required'; Note = $note } }
  if ($mode -eq 'Disabled' -or $mode -eq 'absent') { return @{ Verdict = @{ Outcome = 'not_enforced'; Reason = 'AppLocker rules are configured but the application identity service is disabled or absent, so they are not enforced' }; Note = $note } }
  if ($state -ne 'Running') { return @{ Verdict = @{ Outcome = 'not_enforced'; Reason = 'AppLocker rules are configured but the application identity service is not running, so they are not enforced right now' }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'the application identity service is present and running while AppLocker rules are enforced' }; Note = $note }
}
