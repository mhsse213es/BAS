# CSCRF-FC-02: synthetic files copy to BAS_FC_TARGET and verify by hash (gated; no real data). Removes both sides in undo.
if (-not (Test-CgFcGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_FC_TEST not true; no file copied [CSCRF-FC-02]' } 'fc-02' }
$target = $env:BAS_FC_TARGET
if (-not $target) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_FC_TARGET not set; no copy made [CSCRF-FC-02]' } 'fc-02' }
$src = Join-Path $env:TEMP ('bas-fc-src-' + $script:CgRun)
$dst = Join-Path $target ('bas-fc-' + $script:CgRun)
New-CgUndoRecord 'fc-02' @{ scenario = 'fc-02'; src = $src; dst = $dst }
New-Item -ItemType Directory -Force -Path $src | Out-Null
$marker = "BAS-SYNTHETIC-FC-$($script:CgRun) (no real data)"
1..3 | ForEach-Object { Set-Content -LiteralPath (Join-Path $src "synthetic-$_.txt") -Value "$marker $_" -Encoding ASCII }
try { Copy-Item -LiteralPath $src -Destination $dst -Recurse -ErrorAction Stop } catch { Complete-CgStep @{ Outcome = 'fail'; Reason = 'synthetic copy to BAS_FC_TARGET failed [CSCRF-FC-02]' } 'fc-02' }
$bad = @()
foreach ($f in Get-ChildItem -LiteralPath $src -File) {
  $c = Join-Path $dst $f.Name
  if (-not (Test-Path -LiteralPath $c)) { $bad += "$($f.Name): missing in copy"; continue }
  if ((Get-CgSha256 $f.FullName) -ne (Get-CgSha256 $c)) { $bad += "$($f.Name): hash differs after copy" }
}
if ($bad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = (($bad -join '; ') + ' [CSCRF-FC-02]') } 'fc-02' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'synthetic files copied to the target and verified by SHA256 [CSCRF-FC-02]' } 'fc-02'
