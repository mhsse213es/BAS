# Undo: remove the per-run synthetic folder.
$rec = Read-CgUndoRecord 'bdr-03'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
Remove-Item -LiteralPath $rec.dir -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $rec.dir) { Write-Output "FAIL: residue folder $($rec.dir) survived undo"; exit 0 }
Remove-CgUndoRecord 'bdr-03'
Write-Output 'PASS: Cleanup complete'
exit 0
