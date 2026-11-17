Invoke-AppCtlTest -Family 'supplemental_policy' -Collection 'Exe' -Needle 'CiPolicies' -Technique 'T1562.001' -Direct -Attempt {
  $dir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
  $legacy = Join-Path $env:SystemRoot 'System32\CodeIntegrity\SiPolicy.p7b'
  $dirExists = Test-Path $dir
  $count = if ($dirExists) { @(Get-ChildItem -Path $dir -Filter *.cip -ErrorAction SilentlyContinue).Count } else { 0 }
  $legacyPresent = Test-Path $legacy
  $acl = if ($dirExists) { Get-Acl -Path $dir -ErrorAction SilentlyContinue } else { $null }
  $weak = @()
  if ($acl) {
    foreach ($r in $acl.Access) {
      if ($r.AccessControlType -ne 'Allow') { continue }
      $id = Get-AppCtlAceSid $r
      if ($id -in 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') { continue }
      if ($r.FileSystemRights.ToString() -match 'FullControl|Write|CreateFiles|Modify|ChangePermissions|TakeOwnership') { $weak += $id }
    }
  }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $live = 'live_canary_not_attempted'; $planted = $false
  if ($env:BAS_CONFIRM_APPCONTROL_POLICY_TAMPER -ceq 'true' -and $dirExists) {
    $canary = Join-Path $dir "bas_canary_$($script:AppCtlTid.Substring(0,8)).tmp"
    try { Set-Content -Path $canary -Value 'BAS-SIM canary, not a policy' -ErrorAction Stop; $planted = Test-Path $canary } catch {}
    Remove-Item -Path $canary -Force -ErrorAction SilentlyContinue
    $gone = -not (Test-Path $canary)
    $live = "live_canary_attempted identity_is_admin=$isAdmin planted=$planted removed=$gone"
    if (-not $gone) { Write-Output "WARNING: canary file $canary may remain in the active policy directory; delete it manually. [BAS-SIM]" }
  }
  $note = "active_dir_present=$dirExists cip_policy_files=$count legacy_sipolicy_present=$legacyPresent unprivileged_write_principals=$($weak.Count) $live. A non-policy canary file is used; no policy file is ever written. Whether a base policy accepts supplemental policies is not tested."
  if (-not $dirExists -and -not $legacyPresent) { return @{ NotApplicable = 'no WDAC policy directory or legacy policy file exists on this host, so there is no policy trust boundary to test'; Note = $note } }
  if ($weak.Count -gt 0 -or ($planted -and -not $isAdmin)) { return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = "unprivileged principals can place files in the active WDAC policy directory ($($weak -join ','))" }; Note = $note } }
  if (-not $dirExists) { return @{ Verdict = @{ Outcome = 'inconclusive'; Reason = 'only a legacy single-policy file exists; the multiple-policy directory is absent, so supplemental-policy placement was not tested' }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'the active WDAC policy directory is writable only by SYSTEM, TrustedInstaller and administrators' }; Note = $note }
}
