# CSCRF-BDR-05: the DR target accepts a connection on BAS_DR_PORT (default 3389). Read only; one connection attempt.
$target = $env:BAS_DR_TARGET
if (-not $target) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_DR_TARGET not set; no DR site probed [CSCRF-BDR-05]' } 'bdr-05' }
$port = 3389; if ($env:BAS_DR_PORT) { [int]::TryParse($env:BAS_DR_PORT, [ref]$port) | Out-Null }
if ((Get-CgDrTcp $target $port) -eq 'open') { Complete-CgStep @{ Outcome = 'pass'; Reason = "DR target $target`:$port reachable [CSCRF-BDR-05]" } 'bdr-05' }
Complete-CgStep @{ Outcome = 'fail'; Reason = "DR target $target`:$port not reachable [CSCRF-BDR-05]" } 'bdr-05'
