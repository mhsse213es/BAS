# Undo: remove the synthetic source and the synthetic copy.
$rec = Read-CgUndoRecord 'fc-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
Remove-Item -LiteralPath $rec.src -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $rec.dst -Recurse -Force -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $rec.src) -or (Test-Path -LiteralPath $rec.dst)) { Write-Output 'FAIL: synthetic files survived undo'; exit 0 }
Remove-CgUndoRecord 'fc-02'
Write-Output 'PASS: Cleanup complete'
exit 0
