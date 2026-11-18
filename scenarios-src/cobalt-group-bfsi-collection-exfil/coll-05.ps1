# Cobalt Group BFSI - Exfiltration Over C2 Channel Simulation (coll-05)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'COLL-05'
}
$txId = 'bas-sim-exfil-' + $script:CgRun
$undo_data = @{ scenario = 'coll-05'; txId = $txId }
try { New-CgUndoRecord 'coll-05' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'coll-05' }

$post = Invoke-LedgerExfilPost -Id $txId -Amount 1.0 -Account 'bas-sim-exfil-test'
if ($post.Code -eq 201) {
  $res = @{ Outcome = 'fail'; Reason = 'Synthetic payload exfiltration to the simulated sink succeeded' }
} elseif ($post.Code -eq 403 -or $post.Code -eq 401) {
  $res = @{ Outcome = 'pass'; Reason = 'Exfiltration attempt was blocked by the simulated control' }
} else {
  $res = @{ Outcome = 'error'; Reason = "Exfiltration attempt returned unclassifiable HTTP $($post.Code)" }
}
Complete-CgStep $res 'COLL-05'
