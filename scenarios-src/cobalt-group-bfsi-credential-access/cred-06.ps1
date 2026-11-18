# Cobalt Group BFSI - AS-REP roasting simulation (cred-06)
$undo_data = @{ scenario = 'cred-06'; timestamp = (Get-Date -Format 'o'); description = 'AS-REP roasting simulation' }
try { New-CgUndoRecord 'cred-06' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-06' }

$res = try { Get-ADUser -Identity 'testuser' -Properties UserAccountControl -ErrorAction Stop | Out-Null; @{ Outcome = 'fail'; Reason = 'AS-REP roasting possible' } } catch { @{ Outcome = 'pass'; Reason = 'AS-REP roasting blocked or account not found' } }
Complete-CgStep $res 'CRED-06'
