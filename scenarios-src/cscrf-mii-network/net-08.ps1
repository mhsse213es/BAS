# CSCRF-NET-08: egress to a non-routed documentation address must not connect. A connection means no egress
# filter or an intercepting proxy is present. 192.0.2.1 (RFC 5737) reaches no real destination.
$r = Test-CgTcpPort '192.0.2.1' 443 3000
if ($r -eq 'open') { Complete-CgStep @{ Outcome = 'fail'; Reason = 'connection to 192.0.2.1:443 succeeded; egress filtering or interception is absent [CSCRF-NET-08]' } 'net-08' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'egress to 192.0.2.1:443 not established [CSCRF-NET-08]' } 'net-08'
