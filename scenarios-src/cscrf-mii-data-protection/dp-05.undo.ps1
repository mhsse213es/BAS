# Undo: remove the synthetic marker file.
$rec = Read-CgUndoRecord 'dp-05'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
Remove-Item -LiteralPath $rec.file -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $rec.file) { Write-Output "FAIL: marker $($rec.file) survived undo"; exit 0 }
Remove-CgUndoRecord 'dp-05'
Write-Output 'PASS: Cleanup complete'
exit 0
