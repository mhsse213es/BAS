# Undo: RDP connectivity check
$rec = Read-CgUndoRecord 'lat-01'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

# Clean up any test artifacts (mostly read-only, so minimal cleanup)
Remove-CgUndoRecord 'lat-01'
Write-Output 'PASS: Cleanup complete'
exit 0
