# Undo: Fraudulent Transaction Pattern Simulation
$rec = Read-CgUndoRecord 'fin-04'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

foreach ($id in $rec.txIds) { Remove-CgLedgerTransaction -Id $id }
Remove-CgUndoRecord 'fin-04'
Write-Output 'PASS: Cleanup complete'
exit 0
