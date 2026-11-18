# CSCRF-DP-03: SMB server encrypts data and SMB1 is disabled (read only).
try { $c = Get-SmbServerConfiguration -ErrorAction Stop } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'SMB server configuration could not be read [CSCRF-DP-03]' } 'dp-03' }
$problems = @()
if (-not $c.EncryptData) { $problems += 'SMB encryption not required (EncryptData false)' }
if ($c.EnableSMB1Protocol) { $problems += 'SMB1 enabled' }
if ($problems.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = (($problems -join '; ') + ' [CSCRF-DP-03]') } 'dp-03' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'SMB encryption required and SMB1 disabled [CSCRF-DP-03]' } 'dp-03'
