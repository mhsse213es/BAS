# Cobalt Group BFSI - Browser credential discovery (cred-04)
$undo_data = @{ scenario = 'cred-04'; timestamp = (Get-Date -Format 'o'); description = 'Browser credential discovery' }
try { New-CgUndoRecord 'cred-04' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-04' }

$res = Invoke-BrowserCredentialDiscovery
Complete-CgStep $res 'CRED-04'
