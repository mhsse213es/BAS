# Undo: Local Account Creation Persistence (tolerates the account already being absent)
$rec = Read-CgUndoRecord 'pers-03'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

Remove-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue
Remove-CgUndoRecord 'pers-03'
Write-Output 'PASS: Cleanup complete'
exit 0
