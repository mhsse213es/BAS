# Undo: Local Data Collection from Test Directories
$rec = Read-CgUndoRecord 'coll-01'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found or unreadable'; exit 0 }

if ($rec.testDir -and (Test-Path -LiteralPath $rec.testDir)) {
  Remove-Item -LiteralPath $rec.testDir -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-CgUndoRecord 'coll-01'
Write-Output 'PASS: Cleanup complete'
exit 0
