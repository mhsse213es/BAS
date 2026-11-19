# CSCRF-SIEM-02: the endpoint is pointed at a Windows Event Forwarding subscription manager (read only). Configuration only; it does not show that events reach the collector.
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
$v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue)
$values = @()
if ($v) { $values = @($v.PSObject.Properties | Where-Object { $_.Name -like '1*' } | ForEach-Object { $_.Value }) }
if ($values.Count -gt 0) { Complete-CgStep @{ Outcome = 'pass'; Reason = "subscription manager configured ($($values.Count) entry/entries) [CSCRF-SIEM-02]" } 'siem-02' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'no Windows Event Forwarding subscription manager configured; events are not forwarded by policy [CSCRF-SIEM-02]' } 'siem-02'
