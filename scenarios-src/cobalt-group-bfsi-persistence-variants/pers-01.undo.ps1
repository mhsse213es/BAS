# Undo: Registry Run Key Persistence (removes only the named value, never the Run key)
$rec = Read-CgUndoRecord 'pers-01'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $rec.valueName -ErrorAction SilentlyContinue
Remove-CgUndoRecord 'pers-01'
Write-Output 'PASS: Cleanup complete'
exit 0
