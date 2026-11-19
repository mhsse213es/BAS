Invoke-AppCtlTest -Family 'enforcement_log_health' -Collection 'Exe' -Needle 'LogHealth' -Technique 'T1562.002' -Direct -Attempt {
  $st = Get-AppCtlState
  $needed = @()
  if (@('Exe', 'Dll' | Where-Object { $st.Al[$_] -ne 'NotConfigured' }).Count -gt 0) { $needed += 'Microsoft-Windows-AppLocker/EXE and DLL' }
  if (@('Script', 'Msi' | Where-Object { $st.Al[$_] -ne 'NotConfigured' }).Count -gt 0) { $needed += 'Microsoft-Windows-AppLocker/MSI and Script' }
  if ($st.Wd -ne 'NotConfigured') { $needed += 'Microsoft-Windows-CodeIntegrity/Operational' }
  if ($needed.Count -eq 0) { return @{ NotApplicable = 'no application control policy is configured, so there are no enforcement logs to keep healthy'; Note = 'no_policy' } }
  $bad = @(); $tiny = @()
  foreach ($n in $needed) {
    $l = $null; try { $l = Get-WinEvent -ListLog $n -ErrorAction Stop } catch {}
    if (-not $l) { $bad += "$n(missing)"; continue }
    if (-not $l.IsEnabled) { $bad += "$n(disabled)" }
    if ($l.MaximumSizeInBytes -lt 1MB) { $tiny += $n }
  }
  $note = "channels_checked=$($needed.Count) disabled_or_missing=$($bad.Count) under_1mb=$($tiny.Count)"
  if ($bad.Count -gt 0) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = "$($bad.Count) enforcement log channel(s) are disabled or missing, so blocks would leave no evidence" }; Note = $note } }
  if ($tiny.Count -gt 0) { return @{ Verdict = @{ Outcome = 'inconclusive'; Reason = "$($tiny.Count) enforcement log channel(s) are capped below 1 MB, so block events may be overwritten before they are collected" }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'every enforcement log channel that this policy relies on is enabled and has room to retain events' }; Note = $note }
}
