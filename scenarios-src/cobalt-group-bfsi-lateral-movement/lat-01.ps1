# Cobalt Group BFSI - RDP connectivity check (lat-01)
$target = $env:BAS_TEST_HOST
$undo_data = @{ scenario = 'lat-01'; timestamp = (Get-Date -Format 'o'); description = 'RDP connectivity check'; target = $target }
try { New-CgUndoRecord 'lat-01' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-01' }

if (-not $target) { $res = @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' } }
else { $res = Test-RdpConnectivity -TargetHost $target }
Complete-CgStep $res 'LAT-01'
