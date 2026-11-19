# Cobalt Group BFSI - Lateral tool transfer simulation (lat-06)
$target = $env:BAS_TEST_HOST
$undo_data = @{ scenario = 'lat-06'; timestamp = (Get-Date -Format 'o'); description = 'Lateral tool transfer simulation'; target = $target }
try { New-CgUndoRecord 'lat-06' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-06' }

if (-not $target) {
  $res = @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' }
} else {
  $tmp = New-TemporaryFile
  $res = Invoke-ToolTransferSimulation -SourcePath $tmp.FullName -DestHost $target -DestPath 'C$\Temp\test.bin'
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}
Complete-CgStep $res 'LAT-06'
