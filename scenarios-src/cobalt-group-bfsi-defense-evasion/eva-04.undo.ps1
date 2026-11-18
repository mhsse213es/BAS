# Undo: Masquerading Executable Detection Test
$rec = Read-CgUndoRecord 'eva-04'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

if ($rec.testDir -and (Test-Path -LiteralPath $rec.testDir)) {
  Remove-Item -LiteralPath $rec.testDir -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-CgUndoRecord 'eva-04'
Write-Output 'PASS: Cleanup complete'
exit 0
