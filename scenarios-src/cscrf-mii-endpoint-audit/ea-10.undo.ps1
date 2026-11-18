# Undo: restore the recorded Process Creation audit setting (idempotent).
$GUID = '{0CCE922B-69AE-11D9-BED3-505054503030}'
$rec = $null
try { $rec = Get-Content -LiteralPath (Join-Path $env:TEMP 'bas-cg-undo\ea-10.json') -Raw | ConvertFrom-Json } catch {}
if ($rec -eq $null) { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
$sf = if ($rec.original -band 1) { 'enable' } else { 'disable' }
$ff = if ($rec.original -band 2) { 'enable' } else { 'disable' }
& auditpol.exe /set /subcategory:$GUID /success:$sf /failure:$ff 2>&1 | Out-Null
Remove-Item -LiteralPath (Join-Path $env:TEMP 'bas-cg-undo\ea-10.json') -Force -ErrorAction SilentlyContinue
Write-Output 'PASS: Cleanup complete'
exit 0
