# CSCRF-BDR-01: at least one backup version exists (read only)
$t = Get-CgLatestBackupTime
if ($t -eq 'none') { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no backup version exists on this host (wbadmin: No backup was found) [CSCRF-BDR-01]' } 'bdr-01' }
if ($t -eq $null) { Complete-CgStep @{ Outcome = 'error'; Reason = 'backup versions could not be parsed [CSCRF-BDR-01]' } 'bdr-01' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "backup version present, latest $t [CSCRF-BDR-01]" } 'bdr-01'
