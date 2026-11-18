# CSCRF-NET-06: a connection from zone 1 to zone 2 on a restricted port is refused. Needs a second zone target.
$target = $env:BAS_ZONE2_TARGET
if (-not $target) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_ZONE2_TARGET not set; no second zone available [CSCRF-NET-06]' } 'net-06' }
if (-not (Test-CgPrivateIPv4 $target)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_ZONE2_TARGET must be a private IPv4 address [CSCRF-NET-06]' } 'net-06' }
$port = 445
if ($env:BAS_ZONE2_PORT -and [int]::TryParse($env:BAS_ZONE2_PORT, [ref]$port)) { } else { $port = 445 }
$r = Test-CgTcpPort $target $port 3000
if ($r -eq 'open') { Complete-CgStep @{ Outcome = 'fail'; Reason = "zone 1 reached zone 2 at $target`:$port; segmentation not enforced [CSCRF-NET-06]" } 'net-06' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "zone 2 $target`:$port not reachable from zone 1 [CSCRF-NET-06]" } 'net-06'
