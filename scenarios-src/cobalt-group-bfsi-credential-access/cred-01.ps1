# Cobalt Group BFSI - LSASS simulation (cred-01)
$undo_data = @{ scenario = 'cred-01'; timestamp = (Get-Date -Format 'o'); description = 'LSASS simulation' }
try { New-CgUndoRecord 'cred-01' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-01' }

$res = Invoke-LsassSimulation
Complete-CgStep $res 'CRED-01'
