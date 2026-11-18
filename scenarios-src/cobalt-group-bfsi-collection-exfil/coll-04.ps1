# Cobalt Group BFSI - Archive Collected Data (coll-04)
$testFile = Join-Path $env:TEMP ('bas_sim_coll04_' + $script:CgRun + '.txt')
$archive = Join-Path $env:TEMP ('bas_sim_coll04_' + $script:CgRun + '.zip')
$undo_data = @{ scenario = 'coll-04'; testFile = $testFile; archive = $archive }
try { New-CgUndoRecord 'coll-04' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'coll-04' }

Set-Content -LiteralPath $testFile -Value 'BAS-SIM synthetic collection test data'
try {
  Compress-Archive -Path $testFile -DestinationPath $archive -Force -ErrorAction Stop
  $archived = Test-Path -LiteralPath $archive
} catch { $archived = $false }
Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue

if ($archived) {
  $res = @{ Outcome = 'fail'; Reason = 'Archive creation of collected data succeeded' }
} else {
  $res = @{ Outcome = 'error'; Reason = 'Archive creation did not produce the expected file' }
}
Complete-CgStep $res 'COLL-04'
