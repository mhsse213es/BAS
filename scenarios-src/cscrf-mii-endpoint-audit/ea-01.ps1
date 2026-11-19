# CSCRF-EA-01: the newest installed security update is no more than 60 days old (read only)
try { $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 } catch { $hf = $null }
if (-not $hf) { Complete-CgStep @{ Outcome = 'error'; Reason = 'no installed update history could be read [CSCRF-EA-01]' } 'ea-01' }
$age = [int]((Get-Date) - $hf.InstalledOn).TotalDays
if ($age -gt 60) { Complete-CgStep @{ Outcome = 'fail'; Reason = "newest update $($hf.HotFixID) is $age days old (baseline 60) [CSCRF-EA-01]" } 'ea-01' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "newest update $($hf.HotFixID) is $age days old [CSCRF-EA-01]" } 'ea-01'
