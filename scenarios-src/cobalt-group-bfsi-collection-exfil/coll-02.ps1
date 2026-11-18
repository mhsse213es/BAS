# Cobalt Group BFSI - Network Share Collection (coll-02)
$target = $env:BAS_TEST_HOST
$undo_data = @{ scenario = 'coll-02'; target = $target }
try { New-CgUndoRecord 'coll-02' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'coll-02' }

if (-not $target) {
  $res = @{ Outcome = 'skip'; Reason = 'BAS_TEST_HOST not set' }
} else {
  try {
    $items = Get-ChildItem -Path ("\\" + $target + "\C$") -Force -ErrorAction Stop | Select-Object -First 5
    $res = @{ Outcome = 'fail'; Reason = 'Network share listing succeeded, enumerating files on the test target' }
  } catch {
    $res = @{ Outcome = 'pass'; Reason = 'Network share listing was blocked' }
  }
}
Complete-CgStep $res 'COLL-02'
