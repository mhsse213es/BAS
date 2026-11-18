# Cobalt Group BFSI - SMB admin share enumeration (lat-02)
$undo_data = @{ scenario = 'lat-02'; timestamp = (Get-Date -Format 'o'); description = 'SMB admin share enumeration'; target = $env:BAS_TEST_HOST }
try { New-CgUndoRecord 'lat-02' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-02' }

$res = $host = $env:BAS_TEST_HOST; if (-not $host) { @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' } } else { Test-SmbShareAccess -Host $host -Share 'C$' }
Complete-CgStep $res 'LAT-02'
