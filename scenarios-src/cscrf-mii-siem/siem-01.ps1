# CSCRF-SIEM-01: the endpoint syncs time from a network source, not its local clock (read only)
$out = (& w32tm.exe /query /status 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0 -or $out -notmatch 'Source:') { Complete-CgStep @{ Outcome = 'error'; Reason = 'time service status could not be read [CSCRF-SIEM-01]' } 'siem-01' }
$src = [regex]::Match($out, 'Source:\s*(.+)').Groups[1].Value.Trim()
if ($src -match 'Local CMOS Clock|Free-running|VM IC') { Complete-CgStep @{ Outcome = 'fail'; Reason = "time source is '$src'; not a network time source; event timestamps may drift from the SIEM [CSCRF-SIEM-01]" } 'siem-01' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "time source '$src' [CSCRF-SIEM-01]" } 'siem-01'
