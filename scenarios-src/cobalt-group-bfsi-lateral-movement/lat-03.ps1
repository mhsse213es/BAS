# Cobalt Group BFSI - WinRM remote session (lat-03)
$undo_data = @{ scenario = 'lat-03'; timestamp = (Get-Date -Format 'o'); description = 'WinRM remote session'; target = $env:BAS_TEST_HOST }
try { New-CgUndoRecord 'lat-03' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-03' }

$res = $host = $env:BAS_TEST_HOST; if (-not $host) { @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' } } else { Test-WinrmAvailability -Host $host }
Complete-CgStep $res 'LAT-03'
