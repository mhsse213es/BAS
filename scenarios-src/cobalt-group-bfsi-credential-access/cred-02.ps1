# Cobalt Group BFSI - SAM database simulation (cred-02)
$undo_data = @{ scenario = 'cred-02'; timestamp = (Get-Date -Format 'o'); description = 'SAM database simulation' }
try { New-CgUndoRecord 'cred-02' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-02' }

$res = try { Get-Item 'HKLM:\SAM' -ErrorAction Stop; @{ Outcome = 'fail'; Reason = 'SAM hive accessible' } } catch { @{ Outcome = 'pass'; Reason = 'SAM hive access blocked' } }
Complete-CgStep $res 'CRED-02'
