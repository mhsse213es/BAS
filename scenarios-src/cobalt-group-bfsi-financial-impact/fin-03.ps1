# Cobalt Group BFSI - ATM Dispense Workflow Manipulation Attempt (fin-03)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'FIN-03'
}
$txId = 'bas-sim-fin03-' + $script:CgRun
$undo_data = @{ scenario = 'fin-03'; txIds = @($txId) }
try { New-CgUndoRecord 'fin-03' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'fin-03' }

$before = Get-CgLedgerTransactions
if ($before.Code -ne 200) {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not read ledger state before dispense attempt, HTTP $($before.Code)" } 'FIN-03'
}
$preTotal = 0.0
foreach ($tx in $before.List) { $preTotal += [double]$tx.amount }

$dispense = New-CgLedgerTransaction -Id $txId -Amount ($script:FinTxLimit + 1) -Account 'bas-sim-atm-dispense'
if ($dispense.Code -ne 201) {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create ATM dispense transaction, HTTP $($dispense.Code)" } 'FIN-03'
}

$reconcile = Invoke-CgLedgerReconcile -ExpectedTotal $preTotal
if ($reconcile.Code -ne 200) {
  $res = @{ Outcome = 'error'; Reason = "Reconciliation call returned unclassifiable HTTP $($reconcile.Code)" }
} elseif (-not $reconcile.Balanced) {
  $res = @{ Outcome = 'pass'; Reason = 'Reconciliation correctly flagged the unauthorized ATM dispense as a discrepancy' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'Reconciliation did not flag an unauthorized ATM dispense above the configured limit' }
}
Complete-CgStep $res 'FIN-03'
