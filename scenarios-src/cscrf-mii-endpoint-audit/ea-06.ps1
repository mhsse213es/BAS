# CSCRF-EA-06: no service from the disallowed set is running (read only). Disallowed: Telnet, FTP, TFTP, Remote Registry, SNMP, Simple TCP/IP.
$disallowed = @('TlntSvr', 'FTPSVC', 'tftpd', 'RemoteRegistry', 'SNMP', 'simptcp')
try { $running = Get-Service -ErrorAction Stop | Where-Object { $_.Status -eq 'Running' -and $_.Name -in $disallowed } } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'services could not be read [CSCRF-EA-06]' } 'ea-06' }
if (@($running).Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = ('disallowed service(s) running: ' + (($running | ForEach-Object Name) -join ', ') + ' [CSCRF-EA-06]') } 'ea-06' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'no disallowed service is running [CSCRF-EA-06]' } 'ea-06'
