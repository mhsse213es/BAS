# Undo: System discovery via ping sweep
$rec = Read-CgUndoRecord 'lat-05'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

# Clean up any test artifacts (mostly read-only, so minimal cleanup)
Remove-CgUndoRecord 'lat-05'
Write-Output 'PASS: Cleanup complete'
exit 0
