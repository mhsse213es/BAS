# Cobalt Group BFSI - DNS Exfiltration Simulation (coll-06)
$subdomain = 'bas-sim-' + $script:CgRun + '.invalid'
$probe = Invoke-DnsExfilProbe -Subdomain $subdomain

if ($probe.Resolved) {
  $res = @{ Outcome = 'fail'; Reason = "DNS exfiltration subdomain $subdomain unexpectedly resolved" }
} else {
  $res = @{ Outcome = 'pass'; Reason = "DNS exfiltration subdomain $subdomain did not resolve, as expected for a .invalid TLD" }
}
Complete-CgStep $res 'COLL-06'
