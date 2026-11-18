# CSCRF-SIEM-04: the Security log is large enough and does not overwrite events in circular mode. Baseline: at least 1 GB, not Circular (read only).
try { $log = Get-WinEvent -ListLog Security -ErrorAction Stop } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Security log configuration could not be read [CSCRF-SIEM-04]' } 'siem-04' }
$gb = [math]::Round($log.MaximumSizeInBytes / 1GB, 2)
$problems = @()
if ($log.LogMode -eq 'Circular') { $problems += 'circular mode overwrites old events' }
if ($log.MaximumSizeInBytes -lt 1GB) { $problems += "size $gb GB below 1 GB baseline" }
if ($problems.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = ('Security log: ' + ($problems -join '; ') + ' [CSCRF-SIEM-04]') } 'siem-04' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "Security log $gb GB, mode $($log.LogMode) [CSCRF-SIEM-04]" } 'siem-04'
