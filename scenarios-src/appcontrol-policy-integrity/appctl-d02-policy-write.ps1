Invoke-AppCtlTest -Family 'policy_modification' -Collection 'Exe' -Needle 'SrpV2' -Technique 'T1562.001' -Direct -Attempt {
  $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
  $weak = @(); $keyExists = Test-Path $key
  $acl = if ($keyExists) { Get-Acl -Path $key -ErrorAction SilentlyContinue } else { Get-Acl -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -ErrorAction SilentlyContinue }
  if (-not $acl) { return @{ Verdict = @{ Outcome = 'inconclusive'; Reason = 'the policy registry key permissions could not be read' }; Note = 'acl_unreadable' } }
  foreach ($r in $acl.Access) {
    if ($r.AccessControlType -ne 'Allow') { continue }
    $id = Get-AppCtlAceSid $r
    if ($id -in 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') { continue }
    if ($r.RegistryRights.ToString() -match 'FullControl|WriteKey|SetValue|CreateSubKey|ChangePermissions|TakeOwnership') { $weak += $id }
  }
  $live = 'live_reapply_not_attempted'
  $reapplied = $false
  if ($env:BAS_CONFIRM_APPCONTROL_POLICY_TAMPER -ceq 'true') {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $keyExists) { $live = 'live_reapply_skipped_no_local_policy' }
    elseif (-not $isAdmin) { $live = 'live_reapply_skipped_not_admin' }
    else {
      $xmlFile = Join-Path $script:AppCtlWork 'policy.xml'
      try {
        $xml = Get-AppLockerPolicy -Local -Xml -ErrorAction Stop
        Set-Content -Path $xmlFile -Value $xml -Encoding UTF8
        Set-AppLockerPolicy -XmlPolicy $xmlFile -ErrorAction Stop
        $reapplied = $true; $live = 'live_reapply_attempted identical_policy=true accepted=true'
      } catch { $live = 'live_reapply_attempted identical_policy=true accepted=false' }
    }
  }
  $note = "policy_key_present=$keyExists unprivileged_write_principals=$($weak.Count) $live"
  if ($weak.Count -gt 0) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = "non-administrative principals can write the local AppLocker policy store ($($weak -join ','))" }; Note = $note } }
  if (-not $keyExists) { return @{ NotApplicable = 'no local AppLocker policy store exists on this host, so there is no policy to tamper with'; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'the local AppLocker policy store is writable only by SYSTEM and administrators' }; Note = $note }
}
