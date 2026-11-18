# Undo: Registry Modification Detection Test
$rec = Read-CgUndoRecord 'eva-05'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

if ($rec.keyPath -and (Test-Path -LiteralPath $rec.keyPath)) {
  Remove-Item -Path $rec.keyPath -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-CgUndoRecord 'eva-05'
Write-Output 'PASS: Cleanup complete'
exit 0
