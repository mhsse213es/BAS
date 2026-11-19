# Cobalt Group BFSI - Remote service execution simulation (lat-04)
$target = $env:BAS_TEST_HOST
$undo_data = @{ scenario = 'lat-04'; timestamp = (Get-Date -Format 'o'); description = 'Remote service execution simulation'; target = $target }
try { New-CgUndoRecord 'lat-04' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'lat-04' }

if (-not $target) {
  $res = @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' }
} else {
  try {
    Get-Service -ComputerName $target -ErrorAction Stop | Select-Object -First 3 | Out-Null
    $res = @{ Outcome = 'fail'; Reason = 'Remote service enumeration succeeded' }
  } catch {
    $res = @{ Outcome = 'pass'; Reason = 'Remote service enumeration blocked' }
  }
}
Complete-CgStep $res 'LAT-04'
