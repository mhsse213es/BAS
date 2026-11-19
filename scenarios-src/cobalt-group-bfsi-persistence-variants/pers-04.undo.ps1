# Undo: Account Manipulation via Group Membership (removes membership, then the account; both tolerate already-absent)
$rec = Read-CgUndoRecord 'pers-04'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

Remove-LocalGroupMember -Group $rec.groupName -Member $rec.accountName -ErrorAction SilentlyContinue
Remove-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue
Remove-CgUndoRecord 'pers-04'
Write-Output 'PASS: Cleanup complete'
exit 0
