# Undo: Credential Manager discovery
$rec = Read-CgUndoRecord 'cred-03'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found or unreadable'; exit 0 }

# No state changes in Credential Manager discovery - just verify record and clean up
Remove-CgUndoRecord 'cred-03'
Write-Output 'PASS: Cleanup complete'
exit 0
