# CSCRF-FC-01: every file listed in SHA256SUMS under BAS_FC_TARGET exists and matches (read only).
$dir = $env:BAS_FC_TARGET
if (-not $dir) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_FC_TARGET not set; no off-host copy checked [CSCRF-FC-01]' } 'fc-01' }
$sums = Join-Path $dir 'SHA256SUMS'
if (-not (Test-Path -LiteralPath $sums)) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no SHA256SUMS manifest in the copy target [CSCRF-FC-01]' } 'fc-01' }
$bad = @(); $n = 0
foreach ($line in (Get-Content -LiteralPath $sums)) {
  if (-not $line.Trim()) { continue }
  $parts = $line.Trim() -split '\s+', 2
  if ($parts.Count -ne 2) { $bad += 'malformed manifest line'; continue }
  $p = Join-Path $dir $parts[1]; $n++
  if (-not (Test-Path -LiteralPath $p)) { $bad += "$($parts[1]): missing"; continue }
  if ((Get-CgSha256 $p) -ne $parts[0].ToLowerInvariant()) { $bad += "$($parts[1]): hash differs from manifest" }
}
if ($n -eq 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'SHA256SUMS lists no files [CSCRF-FC-01]' } 'fc-01' }
if ($bad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = (($bad -join '; ') + ' [CSCRF-FC-01]') } 'fc-01' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "$n file(s) in the off-host copy match the manifest [CSCRF-FC-01]" } 'fc-01'
