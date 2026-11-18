# Cobalt Group BFSI - SMB admin share enumeration (lat-02)
$target = $env:BAS_TEST_HOST
$undo_data = @{ scenario = 'lat-02'; timestamp = (Get-Date -Format 'o'); description = 'SMB admin share enumeration'; target = $target }
try { New-CgUndoRecord 'lat-02' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-02' }

if (-not $target) { $res = @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' } }
else { $res = Test-SmbShareAccess -TargetHost $target -Share 'C$' }
Complete-CgStep $res 'LAT-02'
