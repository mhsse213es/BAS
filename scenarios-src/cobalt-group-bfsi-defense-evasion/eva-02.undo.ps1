# Undo: Security Tool Impairment Permission Probe (read-only, nothing was changed)
$rec = Read-CgUndoRecord 'eva-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }
Remove-CgUndoRecord 'eva-02'
Write-Output 'PASS: Cleanup complete'
exit 0
