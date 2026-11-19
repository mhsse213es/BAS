# Cobalt Group BFSI - Fraudulent Transaction Pattern Simulation (fin-04)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'FIN-04'
}
$txIds = 1..5 | ForEach-Object { 'bas-sim-fin04-' + $script:CgRun + '-' + $_ }
$undo_data = @{ scenario = 'fin-04'; txIds = $txIds }
try { New-CgUndoRecord 'fin-04' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'fin-04' }

$before = Get-CgLedgerTransactions
if ($before.Code -ne 200) {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not read ledger state before structuring attempt, HTTP $($before.Code)" } 'FIN-04'
}
$preTotal = 0.0
foreach ($tx in $before.List) { $preTotal += [double]$tx.amount }

$createFailed = $false
foreach ($id in $txIds) {
  $r = New-CgLedgerTransaction -Id $id -Amount 900.00 -Account 'bas-sim-structuring-account'
  if ($r.Code -ne 201) { $createFailed = $true }
}
if ($createFailed) {
  Complete-CgStep @{ Outcome = 'error'; Reason = 'Could not create one or more structured transactions' } 'FIN-04'
}

$reconcile = Invoke-CgLedgerReconcile -ExpectedTotal $preTotal
if ($reconcile.Code -ne 200) {
  $res = @{ Outcome = 'error'; Reason = "Reconciliation call returned unclassifiable HTTP $($reconcile.Code)" }
} elseif (-not $reconcile.Balanced) {
  $res = @{ Outcome = 'pass'; Reason = 'Reconciliation correctly flagged the structured transaction pattern as a discrepancy' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'Reconciliation did not flag a five-transaction structuring pattern under one account' }
}
Complete-CgStep $res 'FIN-04'
