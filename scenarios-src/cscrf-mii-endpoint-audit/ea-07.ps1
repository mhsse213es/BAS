# CSCRF-EA-07: SMB1 is off, the Guest account is disabled and UAC is on (read only)
$bad = @()
try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $smb1 = $null }
if ($smb1 -eq $null) { Complete-CgStep @{ Outcome = 'error'; Reason = 'SMB server configuration could not be read [CSCRF-EA-07]' } 'ea-07' }
if ($smb1) { $bad += 'SMB1 enabled' }
$guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) { $bad += 'Guest account enabled' }
$lua = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($lua -ne 1) { $bad += 'UAC disabled' }
if ($bad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = ('weak local configuration: ' + ($bad -join '; ') + ' [CSCRF-EA-07]') } 'ea-07' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'SMB1 off, Guest disabled, UAC on [CSCRF-EA-07]' } 'ea-07'
