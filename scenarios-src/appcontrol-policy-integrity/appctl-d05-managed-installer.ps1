Invoke-AppCtlTest -Family 'managed_installer' -Collection 'Exe' -Needle 'ManagedInstaller' -Technique 'T1553' -Direct -Attempt {
  $xml = $null
  try { $xml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) } catch {}
  if (-not $xml) { return @{ NotApplicable = 'the effective AppLocker policy is not readable on this host'; Note = 'policy_unreadable' } }
  $col = @($xml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'ManagedInstaller' })
  if ($col.Count -eq 0 -or @($col[0].ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count -eq 0) { return @{ NotApplicable = 'no Managed Installer rule collection is configured, so installer-origin trust cannot be tested'; Note = 'managed_installer_rules=0' } }
  $rules = @($col[0].ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
  $writable = '(?i)(%TEMP%|%TMP%|%APPDATA%|%LOCALAPPDATA%|%USERPROFILE%|\\Users\\|\\Temp\\|\\Downloads\\|%OSDRIVE%\\Users)'
  $risky = @()
  foreach ($r in $rules) {
    foreach ($pc in @($r.SelectNodes('.//FilePathCondition'))) { if ([string]$pc.Path -match $writable) { $risky += [string]$r.Name } }
  }
  $note = "managed_installer_rules=$($rules.Count) rules_with_user_writable_path=$($risky.Count) rule_names_recorded=false"
  if ($risky.Count -gt 0) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = "$($risky.Count) Managed Installer rule(s) trust a user-writable path, so anything run from there becomes a trusted installer" }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = "$($rules.Count) Managed Installer rule(s) are configured and none trusts a user-writable location" }; Note = $note }
}
