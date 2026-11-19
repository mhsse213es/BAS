# Undo: LSASS simulation
$rec = Read-CgUndoRecord 'cred-01'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found or unreadable'; exit 0 }

# No state changes in LSASS simulation - just verify record and clean up
Remove-CgUndoRecord 'cred-01'
Write-Output 'PASS: Cleanup complete'
exit 0
