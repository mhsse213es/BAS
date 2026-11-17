Invoke-A36Test -Id 'k2' -Technique 'T1560.001' -Telemetry @('sysmon:1', 'sec:4688', 'sysmon:11') -Summary 'collected files are archived with a command-line utility and the archive is verified by extraction and hash (T1560.001)' -Attempt {
  $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
  if (-not (Test-Path -LiteralPath $tar)) { return @{ Ran = $false; Note = 'tar_missing'; NotApplicable = 'tar.exe is not present on this host (Windows build below 1803)' } }
  $src = Join-Path $script:A36Work 'collection'
  New-Item -ItemType Directory -Path $src -Force | Out-Null
  1..5 | ForEach-Object { Set-Content -LiteralPath (Join-Path $src "doc$_.txt") -Value ($script:A36Marker + " synthetic $_") -Encoding ASCII }
  $zip = Join-Path $script:A36Work 'collected.zip'
  [void](Invoke-A36Proc -File $tar -ArgLine ('-a -c -f "' + $zip + '" -C "' + $src + '" .') -TimeoutSec 30 -NoShell)
  $listing = @(& $tar -t -f $zip 2>$null | Where-Object { $_ -match 'doc\d\.txt' })
  $restore = Join-Path $script:A36Work 'restored'
  New-Item -ItemType Directory -Path $restore -Force | Out-Null
  [void](Invoke-A36Proc -File $tar -ArgLine ('-x -f "' + $zip + '" -C "' + $restore + '"') -TimeoutSec 30 -NoShell)
  $hashOk = $true
  foreach ($f in @(Get-ChildItem -LiteralPath $src -File)) { $r = Join-Path $restore $f.Name; if (-not (Test-Path -LiteralPath $r) -or (Get-FileHash -LiteralPath $r).Hash -ne (Get-FileHash -LiteralPath $f.FullName).Hash) { $hashOk = $false } }
  $ran = ((Test-Path -LiteralPath $zip) -and $listing.Count -eq 5 -and $hashOk)
  return @{ Ran = $ran; Note = "utility=tar.exe archive_created=$(Test-Path -LiteralPath $zip) entries_listed=$($listing.Count) extracted_hashes_match=$hashOk encrypted=false"; NotApplicable = '' }
}
