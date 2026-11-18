# Cobalt Group BFSI - Recovery and Service Disruption Check (fin-07)
# Read-only resilience smoke check: confirms the lab ledger stays reachable across a short burst of
# GET requests. This does not attempt denial of service against any system.
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'FIN-07'
}

$failures = 0
1..5 | ForEach-Object {
  $r = Get-CgLedgerTransactions
  if ($r.Code -ne 200) { $failures++ }
}

if ($failures -eq 0) {
  $res = @{ Outcome = 'pass'; Reason = 'Ledger remained reachable across a short burst of requests' }
} else {
  $res = @{ Outcome = 'error'; Reason = "Ledger failed to respond on $failures of 5 requests during the resilience check" }
}
Complete-CgStep $res 'FIN-07'
