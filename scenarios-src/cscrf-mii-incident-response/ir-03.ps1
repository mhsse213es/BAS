# CSCRF-IR-03: at least one outbound firewall block rule exists, so a malicious address can be blocked (read only).
# An empty result is FAIL (no block rule). ERROR only when the firewall service cannot be queried.
$svc = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') { Complete-CgStep @{ Outcome = 'error'; Reason = 'Windows Firewall service is not running; rules cannot be read [CSCRF-IR-03]' } 'ir-03' }
$rules = @(Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no enabled outbound block rule exists; blocking a malicious address is not configured [CSCRF-IR-03]' } 'ir-03' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "$($rules.Count) enabled outbound block rule(s) present; coverage of a given address is not tested [CSCRF-IR-03]" } 'ir-03'
