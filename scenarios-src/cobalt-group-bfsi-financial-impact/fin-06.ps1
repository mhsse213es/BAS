# Cobalt Group BFSI - Financial Reconciliation Manipulation Attempt (fin-06)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'FIN-06'
}
$txId = 'bas-sim-fin06-' + $script:CgRun
$undo_data = @{ scenario = 'fin-06'; txIds = @($txId) }
try { New-CgUndoRecord 'fin-06' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'fin-06' }

$post = New-CgLedgerTransaction -Id $txId -Amount 300.00 -Account 'bas-sim-acct-fin06'
if ($post.Code -ne 201) {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create transaction for reconciliation test, HTTP $($post.Code)" } 'FIN-06'
}

$after = Get-CgLedgerTransactions
if ($after.Code -ne 200) {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not read ledger state for reconciliation test, HTTP $($after.Code)" } 'FIN-06'
}
$actualTotal = 0.0
foreach ($tx in $after.List) { $actualTotal += [double]$tx.amount }
$wrongExpected = $actualTotal + 1.0

$reconcile = Invoke-CgLedgerReconcile -ExpectedTotal $wrongExpected
if ($reconcile.Code -ne 200) {
  $res = @{ Outcome = 'error'; Reason = "Reconciliation call returned unclassifiable HTTP $($reconcile.Code)" }
} elseif (-not $reconcile.Balanced) {
  $res = @{ Outcome = 'pass'; Reason = 'Reconciliation correctly flagged a deliberately wrong expected total as unbalanced' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'Reconciliation wrongly reported balanced=true for a deliberately incorrect expected total' }
}
Complete-CgStep $res 'FIN-06'
