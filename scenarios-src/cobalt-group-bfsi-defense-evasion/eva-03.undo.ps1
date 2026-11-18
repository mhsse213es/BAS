# Undo: PowerShell Obfuscation Detection Test (no persistent state created)
$rec = Read-CgUndoRecord 'eva-03'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }
Remove-CgUndoRecord 'eva-03'
Write-Output 'PASS: Cleanup complete'
exit 0
