# Undo: Browser credential discovery
$rec = Read-CgUndoRecord 'cred-04'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found or unreadable'; exit 0 }

# No state changes in Browser credential discovery - just verify record and clean up
Remove-CgUndoRecord 'cred-04'
Write-Output 'PASS: Cleanup complete'
exit 0
