# Cobalt Group BFSI - Credential Manager discovery (cred-03)
$undo_data = @{ scenario = 'cred-03'; timestamp = (Get-Date -Format 'o'); description = 'Credential Manager discovery' }
try { New-CgUndoRecord 'cred-03' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-03' }

$res = Invoke-CredentialManagerDiscovery
Complete-CgStep $res 'CRED-03'
