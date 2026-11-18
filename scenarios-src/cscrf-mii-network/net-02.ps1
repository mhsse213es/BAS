# CSCRF-NET-02: firewall rules are readable and enumerated
try {
  $rules = Get-NetFirewallRule -Enabled True -ErrorAction Stop
  $inAllow = @($rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }).Count
  Complete-CgStep @{ Outcome = 'pass'; Reason = "firewall inventory read: $($rules.Count) enabled rules, $inAllow inbound allow rules [CSCRF-NET-02]" } 'net-02'
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = 'firewall rules could not be read; the control cannot be evaluated [CSCRF-NET-02]' } 'net-02'
}
