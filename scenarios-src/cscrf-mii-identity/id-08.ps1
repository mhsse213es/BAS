# CSCRF-ID-08: no service runs under a non-built-in account that is also an Administrators member (read only)
try {
  $svcs = Get-CimInstance Win32_Service -ErrorAction Stop
  $admins = Get-CgAdminMemberShortNames
} catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'services or Administrators membership could not be read [CSCRF-ID-08]' } 'id-08' }
$builtin = '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|$)'
$hits = @()
foreach ($s in $svcs) {
  if (-not $s.StartName -or $s.StartName -match $builtin) { continue }
  $short = ($s.StartName -split '\\')[-1]
  if ($admins -contains $short) { $hits += "$($s.Name) runs as $($s.StartName)" }
}
if ($hits.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = ('service account(s) with administrator rights: ' + ($hits -join '; ') + ' [CSCRF-ID-08]') } 'id-08' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'no non-built-in service account is an Administrators member [CSCRF-ID-08]' } 'id-08'
