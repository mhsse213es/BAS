# Cobalt Group BFSI - Lateral tool transfer simulation (lat-06)
$undo_data = @{ scenario = 'lat-06'; timestamp = (Get-Date -Format 'o'); description = 'Lateral tool transfer simulation'; target = $env:BAS_TEST_HOST }
try { New-CgUndoRecord 'lat-06' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-06' }

$res = $host = $env:BAS_TEST_HOST; if (-not $host) { @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' } } else { $tmp = New-TemporaryFile; Invoke-ToolTransferSimulation -SourcePath $tmp.FullName -DestHost $host -DestPath 'C$\Temp	est.bin'; Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
Complete-CgStep $res 'LAT-06'
