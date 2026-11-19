# CSCRF-EA-10: an attempt to disable Process Creation auditing must be refused. Gated. The original setting is recorded, restored in this run, and restored again in undo.
if (-not (Test-CgEndpointGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_ENDPOINT_CHANGE not true; audit policy not changed [CSCRF-EA-10]' } 'ea-10' }
$orig = Get-CgProcessCreationSetting
if ($orig -eq $null) { Complete-CgStep @{ Outcome = 'error'; Reason = 'Process Creation audit setting could not be read [CSCRF-EA-10]' } 'ea-10' }
if ($orig -eq 0) { Complete-CgStep @{ Outcome = 'error'; Reason = 'Process Creation auditing was already off before the test; the baseline is unusable, no change made [CSCRF-EA-10]' } 'ea-10' }
New-CgUndoRecord 'ea-10' @{ scenario = 'ea-10'; original = $orig }
& auditpol.exe /set /subcategory:$script:ProcessCreationGuid /success:disable /failure:disable 2>&1 | Out-Null
$after = Get-CgProcessCreationSetting
# Restore in this run so the host is never left without process auditing.
$sf = if ($orig -band 1) { 'enable' } else { 'disable' }
$ff = if ($orig -band 2) { 'enable' } else { 'disable' }
& auditpol.exe /set /subcategory:$script:ProcessCreationGuid /success:$sf /failure:$ff 2>&1 | Out-Null
if ($after -eq 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'Process Creation auditing was disabled; the change was not refused and was restored; verify the EID 4719 alert [CSCRF-EA-10]' } 'ea-10' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'disabling Process Creation auditing was refused [CSCRF-EA-10]' } 'ea-10'
