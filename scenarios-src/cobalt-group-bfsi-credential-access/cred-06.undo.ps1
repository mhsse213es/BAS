# Undo: AS-REP roasting simulation
$rec = Read-CgUndoRecord 'cred-06'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found or unreadable'; exit 0 }

# No state changes in AS-REP roasting simulation - just verify record and clean up
Remove-CgUndoRecord 'cred-06'
Write-Output 'PASS: Cleanup complete'
exit 0
