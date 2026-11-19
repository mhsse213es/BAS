# CSCRF-NET-07: a Telnet connection to the lab target must be refused. Runs only against BAS_LAB_TARGET.
$target = $env:BAS_LAB_TARGET
if (-not $target) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_LAB_TARGET not set; no lab target probed [CSCRF-NET-07]' } 'net-07' }
if (-not (Test-CgPrivateIPv4 $target)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_LAB_TARGET must be a private IPv4 address [CSCRF-NET-07]' } 'net-07' }
$r = Test-CgTcpPort $target 23 3000
if ($r -eq 'open') { Complete-CgStep @{ Outcome = 'fail'; Reason = "Telnet accepted by lab target $target; disallowed clear-text service reachable [CSCRF-NET-07]" } 'net-07' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "Telnet to lab target $target refused or filtered [CSCRF-NET-07]" } 'net-07'
