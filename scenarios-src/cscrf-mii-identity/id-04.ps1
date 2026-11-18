# CSCRF-ID-04: Administrators membership must be within the approved allowlist (read only)
$allow = $env:BAS_ADMIN_ALLOWLIST
if (-not $allow) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_ADMIN_ALLOWLIST not set; no approved membership to compare [CSCRF-ID-04]' } 'id-04' }
$approved = @($allow -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
try { $members = Get-CgAdminMemberShortNames } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Administrators membership could not be read [CSCRF-ID-04]' } 'id-04' }
$extra = @($members | Where-Object { $approved -notcontains $_.ToLowerInvariant() })
if ($extra.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = ('Administrators members not on the approved allowlist: ' + ($extra -join ', ') + ' [CSCRF-ID-04]') } 'id-04' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "all $(@($members).Count) Administrators members are on the approved allowlist [CSCRF-ID-04]" } 'id-04'
