# Cobalt Group BFSI - Account Manipulation via Group Membership (pers-04)
# Adds a synthetic account to the built-in Users group only, never an admin-equivalent group.
$accountName = New-CgTestAccountName 'b'
$undo_data = @{ scenario = 'pers-04'; accountName = $accountName; groupName = 'Users' }
try { New-CgUndoRecord 'pers-04' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'pers-04' }

$password = ConvertTo-SecureString -String ([Guid]::NewGuid().ToString('N') + 'Aa1!') -AsPlainText -Force
try {
  New-LocalUser -Name $accountName -Password $password -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
  Add-LocalGroupMember -Group 'Users' -Member $accountName -ErrorAction Stop
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create account or add group membership: $($_.Exception.Message)" } 'pers-04'
}

$member = Get-LocalGroupMember -Group 'Users' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$accountName" }
if ($member) {
  $res = @{ Outcome = 'pass'; Reason = 'Synthetic account was added to the built-in Users group and membership confirmed' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'Group membership change did not take effect' }
}
Complete-CgStep $res 'pers-04'
