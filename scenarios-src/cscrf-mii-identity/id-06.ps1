# CSCRF-ID-06: local password policy meets the internal baseline (minimum length 12, lockout threshold 1 to 10). Read only.
$out = (net accounts) -join "`n"
$minLen = [regex]::Match($out, 'Minimum password length:\s+(\d+)')
$lock = [regex]::Match($out, 'Lockout threshold:\s+(\S+)')
if (-not $minLen.Success -or -not $lock.Success) { Complete-CgStep @{ Outcome = 'error'; Reason = 'account policy could not be parsed (locale or query failure) [CSCRF-ID-06]' } 'id-06' }
$min = [int]$minLen.Groups[1].Value
$thr = $lock.Groups[1].Value
$problems = @()
if ($min -lt 12) { $problems += "minimum length $min < 12" }
if ($thr -eq 'Never' -or [int]$thr -lt 1 -or [int]$thr -gt 10) { $problems += "lockout threshold $thr outside 1-10" }
if ($problems.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = ('password policy below baseline: ' + ($problems -join '; ') + ' [CSCRF-ID-06]') } 'id-06' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "password policy meets baseline (min length $min, lockout threshold $thr) [CSCRF-ID-06]" } 'id-06'
