# Undo: Network Share Collection (read-only, no state to clean up)
$rec = Read-CgUndoRecord 'coll-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }
Remove-CgUndoRecord 'coll-02'
Write-Output 'PASS: Cleanup complete'
exit 0
