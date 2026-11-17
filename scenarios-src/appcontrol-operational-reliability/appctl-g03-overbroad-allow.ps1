Invoke-AppCtlTest -Family 'overbroad_allow_rules' -Collection 'Exe' -Needle 'AllowRules' -Technique 'T1562.001' -Direct -Attempt {
  $xml = $null
  try { $xml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) } catch {}
  if (-not $xml) { return @{ NotApplicable = 'the effective AppLocker policy is not readable on this host'; Note = 'policy_unreadable' } }
  $rules = @($xml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -in 'Exe', 'Script', 'Dll', 'Msi' } | ForEach-Object { @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.Action -eq 'Allow' }) })
  if ($rules.Count -eq 0) { return @{ NotApplicable = 'the effective AppLocker policy has no allow rules to assess'; Note = 'allow_rules=0' } }
  $risky = 0
  foreach ($r in $rules) {
    if ([string]$r.UserOrGroupSid -ne 'S-1-1-0' -and [string]$r.UserOrGroupSid -ne 'S-1-5-32-545') { continue }
    # Only the rule's own conditions: paths under Exceptions narrow the rule and must not count.
    $wildPub = @($r.SelectNodes('./Conditions/FilePublisherCondition[@PublisherName="*"][@ProductName="*"]')).Count -gt 0
    if ($wildPub) { $risky++; continue }
    foreach ($pc in @($r.SelectNodes('./Conditions/FilePathCondition'))) {
      $p = [string]$pc.Path
      if ($p -eq '*' -or $p -match '(?i)^(%OSDRIVE%\\\*|[A-Z]:\\\*|%TEMP%|%TMP%|%APPDATA%|%LOCALAPPDATA%|%USERPROFILE%|%OSDRIVE%\\Users|\\\\)') { $risky++; break }
    }
  }
  $note = "allow_rules=$($rules.Count) overbroad_for_everyone_or_users=$risky rule_names_recorded=false"
  if ($risky -gt 0) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = "$risky allow rule(s) apply to Everyone or Users and cover a whole drive, a user-writable location or a network path, or that trust any publisher, so they defeat the rest of the policy" }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = "none of the $($rules.Count) allow rule(s) is both open to ordinary users and over a user-writable or whole-drive path" }; Note = $note }
}
