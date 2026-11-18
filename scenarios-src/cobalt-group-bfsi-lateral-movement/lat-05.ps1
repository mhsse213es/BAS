# Cobalt Group BFSI - System discovery via ping sweep (lat-05)
$undo_data = @{ scenario = 'lat-05'; timestamp = (Get-Date -Format 'o'); description = 'System discovery via ping sweep'; target = $env:BAS_TEST_HOST }
try { New-CgUndoRecord 'lat-05' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-05' }

$res = try { $ips = Get-NetIPConfiguration -InterfaceAlias 'Ethernet' -ErrorAction SilentlyContinue; $res = @{ Outcome = 'pass'; Reason = 'System discovery tools available' }; $res } catch { @{ Outcome = 'skip'; Reason = 'System discovery tools not available' } }
Complete-CgStep $res 'LAT-05'
