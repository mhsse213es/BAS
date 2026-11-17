Invoke-AppCtlTest -Family 'writable_allowed_paths' -Collection 'Exe' -Needle 'WindowsWritable' -Technique 'T1553' -Direct -Attempt {
  $st = Get-AppCtlState
  if (-not $st.AlReadable) { return @{ NotApplicable = 'the effective AppLocker policy is not readable on this host'; Note = 'policy_unreadable' } }
  if (@('Exe', 'Script', 'Dll', 'Msi' | Where-Object { $st.Al[$_] -eq 'Enabled' }).Count -eq 0) { return @{ NotApplicable = 'no AppLocker collection is enforced, so writable allow-listed paths are not a bypass here'; Note = 'applocker_not_enforced' } }
  $win = $env:SystemRoot
  $cands = @("$win\Tasks", "$win\Temp", "$win\tracing", "$win\System32\spool\drivers\color", "$win\System32\Tasks", "$win\Registration\CRMLog")
  $found = 0; $checked = 0
  foreach ($d in $cands) {
    if (-not (Test-Path -LiteralPath $d)) { continue }
    $checked++
    $acl = Get-Acl -LiteralPath $d -ErrorAction SilentlyContinue
    if (-not $acl) { continue }
    foreach ($r in $acl.Access) {
      if ($r.AccessControlType -ne 'Allow') { continue }
      $id = [string]$r.IdentityReference
      if ($id -notmatch '^(BUILTIN\\Users|NT AUTHORITY\\Authenticated Users|Everyone)$') { continue }
      if ($r.FileSystemRights.ToString() -match 'FullControl|Modify|Write|CreateFiles') { $found++; break }
    }
  }
  $note = "directories_checked=$checked user_writable_under_windows=$found. ACLs only; nothing is written."
  if ($found -gt 0) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = "$found directory(ies) under the Windows directory are writable by ordinary users; the default path rule trusts the Windows directory, so code placed there would run" }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'none of the checked Windows subdirectories is writable by ordinary users' }; Note = $note }
}
