# CSCRF-EA-08: an effective AppLocker policy exists (read only). Presence of rules is checked, not their quality.
try { $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'effective AppLocker policy could not be read [CSCRF-EA-08]' } 'ea-08' }
$n = @($pol.RuleCollections).Count
$rules = 0
foreach ($c in $pol.RuleCollections) { $rules += $c.Count }
if ($rules -eq 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no effective AppLocker rules; application execution is not restricted [CSCRF-EA-08]' } 'ea-08' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "effective AppLocker policy present ($rules rule(s) in $n collection(s)) [CSCRF-EA-08]" } 'ea-08'
