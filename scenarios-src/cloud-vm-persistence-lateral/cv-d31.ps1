$dirs = @((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'))
$existing = @($dirs | Where-Object { Test-Path -LiteralPath $_ })
$writable = @()
foreach ($d in $existing) {
  $acl = $null
  try { $acl = Get-Acl -LiteralPath $d -ErrorAction Stop } catch {}
  if ($null -eq $acl) { Complete-CvStep @{ Outcome = 'error'; Reason = ('the ACL of a startup location could not be read: ' + $d) } 'CV-D31' }
  $w = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -match '(^|\\)(Users|Authenticated Users|Everyone)$' -and [string]$_.FileSystemRights -match 'Write|Modify|FullControl' })
  if ($w.Count -gt 0) { $writable += $d }
}
Write-Output ('EXEC T1574: read-only ACL check of startup script locations; locations=' + $existing.Count + ' writable_by_non_admin_group=' + $writable.Count + '. Nothing was written.')
if ($writable.Count -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('a startup script location is writable by a non-administrative group (' + ($writable -join '; ') + ')') } 'CV-D31' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'startup script locations are not writable by non-administrative groups' } 'CV-D31'
