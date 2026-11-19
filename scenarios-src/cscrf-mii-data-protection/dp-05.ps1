# CSCRF-DP-05: a synthetic marker written to BAS_DP_SHARE is readable back (gated; no real data). Cleans up in undo.
if (-not (Test-CgDpGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_DP_TEST not true; no marker written [CSCRF-DP-05]' } 'dp-05' }
$share = $env:BAS_DP_SHARE
if (-not $share) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_DP_SHARE not set; no marker written [CSCRF-DP-05]' } 'dp-05' }
$f = Join-Path $share ('bas-dp-marker-' + $script:CgRun + '.txt')
New-CgUndoRecord 'dp-05' @{ scenario = 'dp-05'; file = $f }
$marker = 'BAS-SYNTHETIC-MARKER-' + $script:CgRun + ' (no real data)'
try { Set-Content -LiteralPath $f -Value $marker -Encoding ASCII -ErrorAction Stop } catch { Complete-CgStep @{ Outcome = 'fail'; Reason = 'marker could not be written to BAS_DP_SHARE [CSCRF-DP-05]' } 'dp-05' }
$back = Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue
if ($back -and $back.Trim() -eq $marker) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'synthetic marker written and read back. No DLP block was tested; see CSCRF-DP-06 [CSCRF-DP-05]' } 'dp-05' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'marker read back differently from what was written [CSCRF-DP-05]' } 'dp-05'
