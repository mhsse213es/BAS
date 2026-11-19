Invoke-A36Test -Id 'k4' -Technique 'T1021.006' -Mode Direct -Telemetry @('sysmon:1') -Summary 'WinRM remote-management exposure is read from current configuration only; the service is never started, stopped or reconfigured by this step (T1021.006 posture check)' -Attempt {
  $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
  $running = ($svc -and $svc.Status -eq 'Running')
  $listeners = 0
  if ($running) {
    try { $listeners = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop).Count } catch {}
  }
  $outcome = if ($running -and $listeners -gt 0) { 'allowed_unexpectedly' } else { 'prevented' }
  $reason = if ($running -and $listeners -gt 0) { 'WinRM is running with at least one listener configured, so remote PowerShell is reachable on this host' } else { 'WinRM is not running or has no listener, so remote PowerShell is not currently reachable' }
  return @{ Ran = $true; Note = "winrm_service_status=$($svc.Status) listeners_configured=$listeners service_state_changed_by_this_step=false"; Verdict = @{ Outcome = $outcome; Reason = $reason }; NotApplicable = '' }
}
