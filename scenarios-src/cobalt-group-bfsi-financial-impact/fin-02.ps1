# Cobalt Group BFSI - Payment Instruction Manipulation Attempt (fin-02)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'FIN-02'
}
$txId = 'bas-sim-fin02-' + $script:CgRun
$undo_data = @{ scenario = 'fin-02'; txIds = @($txId) }
try { New-CgUndoRecord 'fin-02' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'fin-02' }

$baseline = New-CgLedgerTransaction -Id $txId -Amount 1200.00 -Account 'bas-sim-beneficiary-original'
if ($baseline.Code -ne 201) {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create baseline payment instruction, HTTP $($baseline.Code)" } 'FIN-02'
}

$tamper = New-CgLedgerTransaction -Id $txId -Amount 1200.00 -Account 'bas-sim-beneficiary-attacker-controlled'
if ($tamper.Code -eq 409) {
  $res = @{ Outcome = 'pass'; Reason = 'Unauthorized beneficiary-account mutation on an existing payment instruction was rejected' }
} elseif ($tamper.Code -eq 200 -or $tamper.Code -eq 201) {
  $res = @{ Outcome = 'fail'; Reason = 'Unauthorized beneficiary-account mutation on an existing payment instruction succeeded' }
} else {
  $res = @{ Outcome = 'error'; Reason = "Payment instruction manipulation attempt returned unclassifiable HTTP $($tamper.Code)" }
}
Complete-CgStep $res 'FIN-02'
