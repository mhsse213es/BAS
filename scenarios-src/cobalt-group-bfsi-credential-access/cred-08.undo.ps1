# Undo: Unsecured credential file discovery
$rec = Read-CgUndoRecord 'cred-08'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found or unreadable'; exit 0 }

# No state changes in Unsecured credential file discovery - just verify record and clean up
Remove-CgUndoRecord 'cred-08'
Write-Output 'PASS: Cleanup complete'
exit 0
