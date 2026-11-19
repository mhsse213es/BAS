# Cobalt Group BFSI - Local Account Creation Persistence (pers-03)
$accountName = New-CgTestAccountName 'a'
$undo_data = @{ scenario = 'pers-03'; accountName = $accountName }
try { New-CgUndoRecord 'pers-03' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'pers-03' }

$password = ConvertTo-SecureString -String ([Guid]::NewGuid().ToString('N') + 'Aa1!') -AsPlainText -Force
try {
  New-LocalUser -Name $accountName -Password $password -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create local account: $($_.Exception.Message)" } 'pers-03'
}

if (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue) {
  $res = @{ Outcome = 'pass'; Reason = 'Local persistence account was created and confirmed present' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'Local account creation did not take effect' }
}
Complete-CgStep $res 'pers-03'
