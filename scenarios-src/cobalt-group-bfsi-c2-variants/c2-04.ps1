# Cobalt Group BFSI - Communication over Non-Standard Port (c2-04)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'C2-04'
}
$simHost = Get-BfsiSimulatorHost
$port = Get-BfsiSimulatorPort

if (@(80, 443, 53) -contains $port) {
  Complete-CgStep @{ Outcome = 'fail'; Reason = "Simulator is bound to well-known port $port, so this step cannot exercise a non-standard port" } 'C2-04'
}

try {
  $r = Invoke-WebRequest -Method GET -Uri ("http://${simHost}:${port}/api/banking/apps") -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
  if ([int]$r.StatusCode -eq 200) {
    $res = @{ Outcome = 'pass'; Reason = "Traffic succeeded over non-standard port $port" }
  } else {
    $res = @{ Outcome = 'fail'; Reason = "Non-standard port responded with HTTP $($r.StatusCode)" }
  }
} catch {
  $res = @{ Outcome = 'error'; Reason = "Non-standard port request failed: $($_.Exception.Message)" }
}
Complete-CgStep $res 'C2-04'
