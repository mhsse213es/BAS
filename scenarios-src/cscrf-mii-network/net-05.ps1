# CSCRF-NET-05: every up adapter has a DNS resolver configured. No approved-resolver baseline is compared yet.
try {
  $up = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
  $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -in $up.Name }
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = 'DNS configuration could not be read [CSCRF-NET-05]' } 'net-05'
}
$missing = @($dns | Where-Object { -not $_.ServerAddresses -or $_.ServerAddresses.Count -eq 0 } | ForEach-Object { $_.InterfaceAlias })
if ($missing.Count -gt 0) {
  Complete-CgStep @{ Outcome = 'fail'; Reason = ('no DNS resolver on up adapter(s): ' + ($missing -join ', ') + ' [CSCRF-NET-05]') } 'net-05'
}
Complete-CgStep @{ Outcome = 'pass'; Reason = 'resolver configured on every up adapter; approved-resolver baseline not compared [CSCRF-NET-05]' } 'net-05'
