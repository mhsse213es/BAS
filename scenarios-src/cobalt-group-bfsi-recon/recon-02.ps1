# Cobalt Group BFSI - Employee and Identity Discovery (recon-02)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'RECON-02'
}
$simHost = Get-BfsiSimulatorHost
$port = Get-BfsiSimulatorPort
try {
  $ids = Invoke-RestMethod -Method GET -Uri ("http://${simHost}:${port}/api/directory/identities") -TimeoutSec 5 -ErrorAction Stop
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Identity directory request failed: $($_.Exception.Message)" } 'RECON-02'
}

if ($ids.Count -eq 0) {
  $res = @{ Outcome = 'fail'; Reason = 'Identity directory returned no identities (a silent empty directory would hide a broken lab)' }
} elseif (($ids | Where-Object { -not ([string]$_.sam).StartsWith('bas-sim-') }).Count -gt 0) {
  $res = @{ Outcome = 'fail'; Reason = 'Identity directory returned an entry that is not clearly synthetic' }
} elseif ($ids.Count -lt 5) {
  $res = @{ Outcome = 'fail'; Reason = "Identity directory returned only $($ids.Count) identities, expected at least 5" }
} else {
  $res = @{ Outcome = 'pass'; Reason = "Enumerated $($ids.Count) synthetic identities from the lab directory" }
}
Complete-CgStep $res 'RECON-02'
