# CSCRF-NET-03: every firewall profile is enabled and does not explicitly allow inbound by default.
# NotConfigured means no explicit default is set; Windows then applies its built-in inbound Block, so it is accepted here.
# Read only, no change.
try {
  $profiles = Get-NetFirewallProfile -ErrorAction Stop
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = 'firewall profile state could not be read [CSCRF-NET-03]' } 'net-03'
}
$bad = @($profiles | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -eq 'Allow' } | ForEach-Object { $_.Name })
if ($bad.Count -gt 0) {
  Complete-CgStep @{ Outcome = 'fail'; Reason = ('profile(s) disabled or explicitly allowing inbound by default: ' + ($bad -join ', ') + ' [CSCRF-NET-03]') } 'net-03'
}
Complete-CgStep @{ Outcome = 'pass'; Reason = 'all firewall profiles enabled and none explicitly allows inbound by default [CSCRF-NET-03]' } 'net-03'
