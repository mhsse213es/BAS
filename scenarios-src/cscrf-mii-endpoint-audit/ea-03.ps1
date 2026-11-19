# CSCRF-EA-03: Defender real-time protection and antivirus are enabled (read only)
try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Defender status could not be read [CSCRF-EA-03]' } 'ea-03' }
$bad = @()
if (-not $st.RealTimeProtectionEnabled) { $bad += 'real-time protection off' }
if (-not $st.AntivirusEnabled) { $bad += 'antivirus off' }
if ($bad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = ('Defender: ' + ($bad -join ', ') + ' [CSCRF-EA-03]') } 'ea-03' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "Defender real-time protection and antivirus enabled (signatures $($st.AntivirusSignatureAge) day(s) old) [CSCRF-EA-03]" } 'ea-03'
