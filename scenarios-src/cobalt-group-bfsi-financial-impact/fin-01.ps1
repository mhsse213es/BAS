# Cobalt Group BFSI - Transaction Record Manipulation Attempt (fin-01)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'FIN-01'
}
$txId = 'bas-sim-fin01-' + $script:CgRun
$undo_data = @{ scenario = 'fin-01'; txIds = @($txId) }
try { New-CgUndoRecord 'fin-01' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'fin-01' }

$baseline = New-CgLedgerTransaction -Id $txId -Amount 500.00 -Account 'bas-sim-acct-fin01'
if ($baseline.Code -ne 201) {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create baseline transaction, HTTP $($baseline.Code)" } 'FIN-01'
}

$tamper = New-CgLedgerTransaction -Id $txId -Amount 999999.00 -Account 'bas-sim-acct-fin01'
if ($tamper.Code -eq 409) {
  $res = @{ Outcome = 'pass'; Reason = 'In-place amount change on an existing transaction record was rejected' }
} elseif ($tamper.Code -eq 200 -or $tamper.Code -eq 201) {
  $res = @{ Outcome = 'fail'; Reason = 'In-place amount change on an existing transaction record succeeded' }
} else {
  $res = @{ Outcome = 'error'; Reason = "Transaction manipulation attempt returned unclassifiable HTTP $($tamper.Code)" }
}
Complete-CgStep $res 'FIN-01'
