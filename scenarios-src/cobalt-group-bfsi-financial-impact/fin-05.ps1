# Cobalt Group BFSI - Transaction Limit Bypass Attempt (fin-05)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'FIN-05'
}
$txId = 'bas-sim-fin05-' + $script:CgRun
$overLimitAmount = $script:FinTxLimit + 1
$undo_data = @{ scenario = 'fin-05'; txIds = @($txId) }
try { New-CgUndoRecord 'fin-05' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'fin-05' }

$post = New-CgLedgerTransaction -Id $txId -Amount $overLimitAmount -Account 'bas-sim-acct-fin05'
if ($post.Code -eq 201) {
  $res = @{ Outcome = 'fail'; Reason = "A transaction of $overLimitAmount, exceeding the configured per-transaction limit of $($script:FinTxLimit), was accepted without a limit check" }
} elseif ($post.Code -eq 403 -or $post.Code -eq 409) {
  $res = @{ Outcome = 'pass'; Reason = 'The over-limit transaction was rejected' }
} else {
  $res = @{ Outcome = 'error'; Reason = "Transaction limit bypass attempt returned unclassifiable HTTP $($post.Code)" }
}
Complete-CgStep $res 'FIN-05'
