# Cobalt Group BFSI - HTTP/S Application-Layer Beaconing (c2-01)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'C2-01'
}
$simHost = Get-BfsiSimulatorHost
$port = Get-BfsiSimulatorPort
$uri = "http://${simHost}:${port}/api/banking/apps"

$stamps = @()
$ok = 0
for ($i = 0; $i -lt 5; $i++) {
  try {
    $r = Invoke-WebRequest -Method GET -Uri $uri -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    if ([int]$r.StatusCode -eq 200) { $ok++ }
  } catch {}
  $stamps += (Get-Date)
  if ($i -lt 4) { Start-Sleep -Seconds 1 }
}

$regular = $true
for ($i = 1; $i -lt $stamps.Count; $i++) {
  $gap = ($stamps[$i] - $stamps[$i - 1]).TotalSeconds
  if ($gap -lt 0.5 -or $gap -gt 3.0) { $regular = $false }
}

if ($ok -eq 5 -and $regular) {
  $res = @{ Outcome = 'pass'; Reason = 'Five HTTP beacons succeeded at a regular interval (each gap between 0.5 and 3.0 seconds)' }
} elseif ($ok -eq 0) {
  $res = @{ Outcome = 'error'; Reason = 'No beacon request succeeded against the simulator' }
} else {
  $res = @{ Outcome = 'fail'; Reason = "Only $ok of 5 beacons succeeded or timestamps were not periodic" }
}
Complete-CgStep $res 'C2-01'
