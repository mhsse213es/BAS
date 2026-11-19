# CSCRF-NET-01: management ports must not be reachable from the lab subnet
$cidr = $env:BAS_LAB_SUBNET
if (-not $cidr) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_LAB_SUBNET not set; no subnet probed [CSCRF-NET-01]' } 'net-01' }
$parts = $cidr -split '/'
$bits = 0
if ($parts.Count -ne 2 -or -not [int]::TryParse($parts[1], [ref]$bits) -or -not (Test-CgPrivateIPv4 $parts[0]) -or $bits -lt 26 -or $bits -gt 30) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_LAB_SUBNET must be a private IPv4 /26 to /30 (at most 62 hosts) [CSCRF-NET-01]' } 'net-01'
}
$base = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
$hosts = 1..([int]([Math]::Pow(2, 32 - $bits)) - 2)
$exposed = @()
$ports = @(445, 3389, 5985)
foreach ($h in $hosts) {
  $b = $base.Clone(); $b[3] = [byte](($base[3] -band (256 - [int][Math]::Pow(2, 32 - $bits))) + $h)
  $ip = ($b -join '.')
  foreach ($p in $ports) { if ((Test-CgTcpPort $ip $p 300) -eq 'open') { $exposed += "$ip`:$p" } }
}
if ($exposed.Count -gt 0) {
  Complete-CgStep @{ Outcome = 'fail'; Reason = ('management port(s) reachable from lab subnet: ' + ($exposed -join ', ') + ' [CSCRF-NET-01]') } 'net-01'
}
Complete-CgStep @{ Outcome = 'pass'; Reason = 'no SMB, RDP or WinRM listener reachable from the lab subnet [CSCRF-NET-01]' } 'net-01'
