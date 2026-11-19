# Undo: Archive Collected Data
$rec = Read-CgUndoRecord 'coll-04'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

if ($rec.testFile -and (Test-Path -LiteralPath $rec.testFile)) { Remove-Item -LiteralPath $rec.testFile -Force -ErrorAction SilentlyContinue }
if ($rec.archive -and (Test-Path -LiteralPath $rec.archive)) { Remove-Item -LiteralPath $rec.archive -Force -ErrorAction SilentlyContinue }
Remove-CgUndoRecord 'coll-04'
Write-Output 'PASS: Cleanup complete'
exit 0
