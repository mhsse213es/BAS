# Undo: Ingress tool transfer (removes only the downloaded file and its per-run directory if empty)
$rec = Read-CgUndoRecord 'c2-03'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

Remove-Item -LiteralPath $rec.file -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $rec.dir -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Split-Path -Parent $rec.dir) -Force -ErrorAction SilentlyContinue
Remove-CgUndoRecord 'c2-03'
Write-Output 'PASS: Cleanup complete'
exit 0
