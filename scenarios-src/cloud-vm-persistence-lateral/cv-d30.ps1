try { $listeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop) } catch { Complete-CvStep @{ Outcome = 'error'; Reason = 'the WinRM listener configuration could not be read' } 'CV-D30' }
$allow = @()
try { $allow = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop | Get-NetFirewallPortFilter -ErrorAction Stop | Where-Object { $_.LocalPort -match '5985|5986' }) } catch { Complete-CvStep @{ Outcome = 'error'; Reason = 'inbound firewall rules could not be read' } 'CV-D30' }
Write-Output ('EXEC T1021: read-only WinRM check (no service or listener change); listeners=' + $listeners.Count + ' inbound_allow_rules_5985_5986=' + $allow.Count)
if ($listeners.Count -gt 0 -and $allow.Count -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = 'a WinRM listener is configured and an inbound firewall allow rule covers 5985 or 5986' } 'CV-D30' }
if ($listeners.Count -gt 0) { Complete-CvStep @{ Outcome = 'pass'; Reason = 'a WinRM listener exists but no inbound firewall allow rule exposes it' } 'CV-D30' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'no WinRM listener is configured on this host' } 'CV-D30'
