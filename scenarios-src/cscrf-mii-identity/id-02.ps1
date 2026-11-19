# CSCRF-ID-02: a new account must not be created directly in Administrators
if (-not (Test-CgIdentityGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_IDENTITY_CHANGE not true; no account created [CSCRF-ID-02]' } 'id-02' }
$name = New-CgIdName
New-CgUndoRecord 'id-02' @{ scenario = 'id-02'; accountName = $name }
try {
  New-LocalUser -Name $name -Password (ConvertTo-SecureString (New-CgSynthPassword) -AsPlainText -Force) -AccountNeverExpires -ErrorAction Stop | Out-Null
} catch { Complete-CgStep @{ Outcome = 'error'; Reason = "could not create synthetic account: $($_.Exception.Message) [CSCRF-ID-02]" } 'id-02' }
try {
  Add-LocalGroupMember -SID $script:AdminSid -Member $name -ErrorAction Stop
} catch {
  Complete-CgStep @{ Outcome = 'pass'; Reason = "adding the new account to Administrators was refused: $($_.Exception.Message) [CSCRF-ID-02]" } 'id-02'
}
Complete-CgStep @{ Outcome = 'fail'; Reason = "new account placed in Administrators; verify EID 4720 with EID 4732 alerts in the SIEM [CSCRF-ID-02]" } 'id-02'
