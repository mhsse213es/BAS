# Cobalt Group BFSI - Password spraying simulation (cred-07)
$undo_data = @{ scenario = 'cred-07'; timestamp = (Get-Date -Format 'o'); description = 'Password spraying simulation' }
try { New-CgUndoRecord 'cred-07' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-07' }

$res = try { $users = @('testuser1', 'testuser2'); $pwd = ConvertTo-SecureString 'wrongpassword' -AsPlainText -Force; foreach ($u in $users) { $cred = New-Object System.Management.Automation.PSCredential($u, $pwd); $null = Get-ADUser -Identity $u -Credential $cred -ErrorAction Stop } @{ Outcome = 'fail'; Reason = 'Password spray succeeded' } } catch { @{ Outcome = 'pass'; Reason = 'Password spray blocked' } }
Complete-CgStep $res 'CRED-07'
