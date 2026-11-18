# Cobalt Group BFSI - RDP connectivity check (lat-01)
$undo_data = @{ scenario = 'lat-01'; timestamp = (Get-Date -Format 'o'); description = 'RDP connectivity check'; target = $env:BAS_TEST_HOST }
try { New-CgUndoRecord 'lat-01' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-01' }

$res = $host = $env:BAS_TEST_HOST; if (-not $host) { @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' } } else { Test-RdpConnectivity -Host $host }
Complete-CgStep $res 'LAT-01'
