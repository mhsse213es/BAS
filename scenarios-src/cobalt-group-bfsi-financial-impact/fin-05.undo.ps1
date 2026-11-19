# Undo: Transaction Limit Bypass Attempt
$rec = Read-CgUndoRecord 'fin-05'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

foreach ($id in $rec.txIds) { Remove-CgLedgerTransaction -Id $id }
Remove-CgUndoRecord 'fin-05'
Write-Output 'PASS: Cleanup complete'
exit 0
