# CSCRF-EA-05: Sysmon is installed and running (read only; the service is not stopped)
$svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('Sysmon', 'Sysmon64') } | Select-Object -First 1
if (-not $svc) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'Sysmon service is not installed [CSCRF-EA-05]' } 'ea-05' }
if ($svc.Status -ne 'Running') { Complete-CgStep @{ Outcome = 'fail'; Reason = "Sysmon service $($svc.Name) is $($svc.Status) [CSCRF-EA-05]" } 'ea-05' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "Sysmon service $($svc.Name) is running [CSCRF-EA-05]" } 'ea-05'
