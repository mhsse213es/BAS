# Undo: Exfiltration Over C2 Channel Simulation
$rec = Read-CgUndoRecord 'coll-05'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

if ($rec.txId) { Remove-LedgerTransaction -Id $rec.txId }
Remove-CgUndoRecord 'coll-05'
Write-Output 'PASS: Cleanup complete'
exit 0
