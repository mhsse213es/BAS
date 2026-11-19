# CSCRF-MII-04: BAS_MII_RECON_PATH holds a reconciliation report written in the last 24 hours (read only).
$dir = $env:BAS_MII_RECON_PATH
if (-not $dir) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_MII_RECON_PATH not set; no reconciliation evidence checked [CSCRF-MII-04]' } 'mii-04' }
if (-not (Test-Path -LiteralPath $dir)) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'reconciliation evidence path does not exist [CSCRF-MII-04]' } 'mii-04' }
$newest = Get-ChildItem -LiteralPath $dir -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $newest) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'no reconciliation report found [CSCRF-MII-04]' } 'mii-04' }
$age = [math]::Round(((Get-Date) - $newest.LastWriteTime).TotalHours, 1)
if ($age -gt 24) { Complete-CgStep @{ Outcome = 'fail'; Reason = "newest reconciliation report is $age h old (limit 24 h) [CSCRF-MII-04]" } 'mii-04' }
Complete-CgStep @{ Outcome = 'pass'; Reason = "newest reconciliation report is $age h old [CSCRF-MII-04]" } 'mii-04'
