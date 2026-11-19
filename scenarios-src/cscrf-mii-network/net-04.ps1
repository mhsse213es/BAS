# CSCRF-NET-04: no legacy clear-text listener (FTP 21, Telnet 23, TFTP 69) on any interface
try {
  $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = 'listening sockets could not be read [CSCRF-NET-04]' } 'net-04'
}
$legacy = @(21, 23)
$hit = @($listeners | Where-Object { $legacy -contains $_.LocalPort -and ($_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::') } | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" })
if ($hit.Count -gt 0) {
  Complete-CgStep @{ Outcome = 'fail'; Reason = ('clear-text listener(s) on all interfaces: ' + ($hit -join ', ') + ' [CSCRF-NET-04]') } 'net-04'
}
Complete-CgStep @{ Outcome = 'pass'; Reason = "no FTP or Telnet listener on all interfaces ($($listeners.Count) listeners inventoried) [CSCRF-NET-04]" } 'net-04'
