Invoke-AppCtlTest -Family 'sideloading_policy' -Collection 'Exe' -Needle 'AppModelUnlock' -Technique 'T1553' -Direct -Attempt {
  $st = Get-AppCtlState
  $enforcing = (@('Exe', 'Script', 'Dll', 'Msi' | Where-Object { $st.Al[$_] -eq 'Enabled' }).Count -gt 0) -or ($st.Wd -eq 'Enabled')
  $vals = @{}
  foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock') {
    foreach ($n in 'AllowAllTrustedApps', 'AllowDevelopmentWithoutDevLicense') {
      $v = $null; try { $v = (Get-ItemProperty -Path $k -Name $n -ErrorAction Stop).$n } catch {}
      if ($null -ne $v) { $vals["$n"] = [int]$v }
    }
  }
  $dev = ($vals['AllowDevelopmentWithoutDevLicense'] -eq 1)
  $trusted = ($vals['AllowAllTrustedApps'] -eq 1)
  $note = "allow_all_trusted_apps=$trusted developer_mode=$dev enforcement_present=$enforcing"
  if (-not $enforcing) { return @{ NotApplicable = 'no application control policy is enforcing, so the sideloading settings do not weaken anything'; Note = $note } }
  if ($dev) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = 'developer mode is on, so loose and unsigned packages can be installed while application control is enforcing' }; Note = $note } }
  if ($trusted) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = 'sideloading of any trusted-signed package is allowed while application control is enforcing' }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'sideloading and developer mode are not enabled' }; Note = $note }
}
