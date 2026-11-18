# CSCRF-MII-01: every sealed trade log under BAS_MII_LOG_PATH matches its .sha256 manifest (read only).
$dir = $env:BAS_MII_LOG_PATH
if (-not $dir) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_MII_LOG_PATH not set; no trade log checked [CSCRF-MII-01]' } 'mii-01' }
if (-not (Test-Path -LiteralPath $dir)) { Complete-CgStep @{ Outcome = 'error'; Reason = "BAS_MII_LOG_PATH does not exist [CSCRF-MII-01]" } 'mii-01' }
$sealed = @(Get-ChildItem -LiteralPath $dir -Filter '*.sealed' -File)
if ($sealed.Count -eq 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no sealed trade logs found; logs are not closed with a manifest [CSCRF-MII-01]' } 'mii-01' }
$bad = @()
foreach ($f in $sealed) {
  $m = "$($f.FullName).sha256"
  if (-not (Test-Path -LiteralPath $m)) { $bad += "$($f.Name): no manifest"; continue }
  $want = ((Get-Content -LiteralPath $m -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
  if ((Get-CgSha256 $f.FullName) -ne $want) { $bad += "$($f.Name): hash differs from manifest" }
}
if ($bad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = (($bad -join '; ') + ' [CSCRF-MII-01]') } 'mii-01' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "$($sealed.Count) sealed trade log(s) match their manifests [CSCRF-MII-01]" } 'mii-01'
