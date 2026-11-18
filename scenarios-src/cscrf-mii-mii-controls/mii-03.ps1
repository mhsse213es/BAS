# CSCRF-MII-03: every service named in BAS_MII_SERVICES is installed and running (read only).
$names = $env:BAS_MII_SERVICES
if (-not $names) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_MII_SERVICES not set; no MII service named [CSCRF-MII-03]' } 'mii-03' }
$bad = @(); $ok = 0
foreach ($n in ($names -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
  $s = Get-Service -Name $n -ErrorAction SilentlyContinue
  if (-not $s) { $bad += "$n not installed"; continue }
  if ($s.Status -ne 'Running') { $bad += "$n is $($s.Status)"; continue }
  $ok++
}
if ($bad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = (($bad -join '; ') + ' [CSCRF-MII-03]') } 'mii-03' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "$ok named MII service(s) running [CSCRF-MII-03]" } 'mii-03'
