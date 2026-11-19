# CSCRF-MII-02: SHA256SUMS under BAS_MII_SETTLEMENT_PATH exists and every listed file matches (read only).
$dir = $env:BAS_MII_SETTLEMENT_PATH
if (-not $dir) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_MII_SETTLEMENT_PATH not set; no settlement files checked [CSCRF-MII-02]' } 'mii-02' }
$sums = Join-Path $dir 'SHA256SUMS'
if (-not (Test-Path -LiteralPath $sums)) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no SHA256SUMS baseline in the settlement path [CSCRF-MII-02]' } 'mii-02' }
$bad = @(); $n = 0
foreach ($line in (Get-Content -LiteralPath $sums)) {
  if (-not $line.Trim()) { continue }
  $parts = $line.Trim() -split '\s+', 2
  if ($parts.Count -ne 2) { $bad += "malformed line"; continue }
  $p = Join-Path $dir $parts[1]; $n++
  if (-not (Test-Path -LiteralPath $p)) { $bad += "$($parts[1]): missing"; continue }
  if ((Get-CgSha256 $p) -ne $parts[0].ToLowerInvariant()) { $bad += "$($parts[1]): hash differs from baseline" }
}
if ($n -eq 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'SHA256SUMS lists no files [CSCRF-MII-02]' } 'mii-02' }
if ($bad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = (($bad -join '; ') + ' [CSCRF-MII-02]') } 'mii-02' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "$n settlement file(s) match the SHA256SUMS baseline [CSCRF-MII-02]" } 'mii-02'
