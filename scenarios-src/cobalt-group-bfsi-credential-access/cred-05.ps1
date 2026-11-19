# Cobalt Group BFSI - Kerberoasting simulation (cred-05)
$undo_data = @{ scenario = 'cred-05'; timestamp = (Get-Date -Format 'o'); description = 'Kerberoasting simulation' }
try { New-CgUndoRecord 'cred-05' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-05' }

$res = try { $spn = 'HTTP/testapp.lab'; $t = klist.exe -l 2>&1; if ($t -match $spn) { @{ Outcome = 'fail'; Reason = 'Kerberoasting succeeded' } } else { @{ Outcome = 'pass'; Reason = 'Kerberoasting blocked' } } } catch { @{ Outcome = 'error'; Reason = 'Kerberoasting test failed' } }
Complete-CgStep $res 'CRED-05'
