# CSCRF-BDR-02: the latest recovery point is no older than 24 hours (read only). Baseline RPO 24 h.
$t = Get-CgLatestBackupTime
if ($t -eq 'none') { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no recovery point exists; RPO is undefined (see CSCRF-BDR-01) [CSCRF-BDR-02]' } 'bdr-02' }
if ($t -eq $null) { Complete-CgStep @{ Outcome = 'error'; Reason = 'backup times could not be parsed [CSCRF-BDR-02]' } 'bdr-02' }
$age = [math]::Round(((Get-Date) - $t).TotalHours, 1)
if ($age -gt 24) { Complete-CgStep @{ Outcome = 'fail'; Reason = "latest recovery point is $age h old (baseline 24 h) [CSCRF-BDR-02]" } 'bdr-02' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "latest recovery point is $age h old [CSCRF-BDR-02]" } 'bdr-02'
