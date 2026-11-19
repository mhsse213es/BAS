# CSCRF-DP-04: the DLP agent service named in BAS_DLP_SERVICE exists and is running (read only). SKIP when unset.
$n = $env:BAS_DLP_SERVICE
if (-not $n) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_DLP_SERVICE not set; no DLP agent named [CSCRF-DP-04]' } 'dp-04' }
$s = Get-Service -Name $n -ErrorAction SilentlyContinue
if (-not $s) { Complete-CgStep @{ Outcome = 'fail'; Reason = "DLP service '$n' is not installed [CSCRF-DP-04]" } 'dp-04' }
if ($s.Status -ne 'Running') { Complete-CgStep @{ Outcome = 'fail'; Reason = "DLP service '$n' is installed but $($s.Status) [CSCRF-DP-04]" } 'dp-04' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "DLP service '$n' is running. Blocking behaviour is not tested here (see CSCRF-DP-06) [CSCRF-DP-04]" } 'dp-04'
