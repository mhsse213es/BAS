# CSCRF-ID-01: an unapproved change of privileged group membership must be blocked
if (-not (Test-CgIdentityGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_IDENTITY_CHANGE not true; no account or group changed [CSCRF-ID-01]' } 'id-01' }
$name = New-CgIdName
New-CgUndoRecord 'id-01' @{ scenario = 'id-01'; accountName = $name }
try {
  New-LocalUser -Name $name -Password (ConvertTo-SecureString (New-CgSynthPassword) -AsPlainText -Force) -AccountNeverExpires -ErrorAction Stop | Out-Null
} catch { Complete-CgStep @{ Outcome = 'error'; Reason = "could not create synthetic account: $($_.Exception.Message) [CSCRF-ID-01]" } 'id-01' }
try {
  Add-LocalGroupMember -SID $script:AdminSid -Member $name -ErrorAction Stop
} catch {
  Complete-CgStep @{ Outcome = 'pass'; Reason = "privileged group add refused: $($_.Exception.Message) [CSCRF-ID-01]" } 'id-01'
}
Remove-LocalGroupMember -SID $script:AdminSid -Member $name -ErrorAction SilentlyContinue
Complete-CgStep @{ Outcome = 'fail'; Reason = "privileged group add succeeded and was reverted; verify the EID 4732 alert in the SIEM [CSCRF-ID-01]" } 'id-01'
