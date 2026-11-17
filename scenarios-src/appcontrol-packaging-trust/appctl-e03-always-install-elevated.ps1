Invoke-AppCtlTest -Family 'always_install_elevated' -Collection 'Msi' -Needle 'AlwaysInstallElevated' -Technique 'T1548' -Direct -Attempt {
  $m = $null; $u = $null
  try { $m = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated } catch {}
  try { $u = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated } catch {}
  $note = "machine_value=$(if ($null -eq $m) { 'unset' } else { $m }) user_value=$(if ($null -eq $u) { 'unset' } else { $u })"
  if ($m -eq 1 -and $u -eq 1) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = 'AlwaysInstallElevated is on for both machine and user, so any MSI installs with SYSTEM rights and MSI rules are not a boundary' }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'AlwaysInstallElevated is not enabled for both machine and user' }; Note = $note }
}
