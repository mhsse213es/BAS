# Undo: SAM database simulation
$rec = Read-CgUndoRecord 'cred-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found or unreadable'; exit 0 }

# No state changes in SAM database simulation - just verify record and clean up
Remove-CgUndoRecord 'cred-02'
Write-Output 'PASS: Cleanup complete'
exit 0
