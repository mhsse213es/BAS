# Cobalt Group BFSI - WinRM remote session (lat-03)
$target = $env:BAS_TEST_HOST
$undo_data = @{ scenario = 'lat-03'; timestamp = (Get-Date -Format 'o'); description = 'WinRM remote session'; target = $target }
try { New-CgUndoRecord 'lat-03' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-03' }

if (-not $target) { $res = @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' } }
else { $res = Test-WinrmAvailability -TargetHost $target }
Complete-CgStep $res 'LAT-03'
