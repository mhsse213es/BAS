# Undo: Valid Local Account Logon (removes the synthetic account; tolerates it already being absent)
$rec = Read-CgUndoRecord 'acc-01'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

Remove-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue
Remove-CgUndoRecord 'acc-01'
Write-Output 'PASS: Cleanup complete'
exit 0
