# Undo: Payment Instruction Manipulation Attempt
$rec = Read-CgUndoRecord 'fin-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

foreach ($id in $rec.txIds) { Remove-CgLedgerTransaction -Id $id }
Remove-CgUndoRecord 'fin-02'
Write-Output 'PASS: Cleanup complete'
exit 0
