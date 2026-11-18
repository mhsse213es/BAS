# Cobalt Group BFSI - Local Data Collection from Test Directories (coll-01)
$testDir = Join-Path $env:TEMP ('bas_sim_coll01_' + $script:CgRun)
$undo_data = @{ scenario = 'coll-01'; testDir = $testDir }
try { New-CgUndoRecord 'coll-01' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'coll-01' }

New-Item -ItemType Directory -Force -Path $testDir | Out-Null
1..3 | ForEach-Object { Set-Content -LiteralPath (Join-Path $testDir "bas_sim_file_$_.txt") -Value 'BAS-SIM synthetic test data' }
$found = @(Get-ChildItem -Path $testDir -Filter 'bas_sim_*' -File -ErrorAction SilentlyContinue)
Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue

if ($found.Count -eq 3) {
  $res = @{ Outcome = 'fail'; Reason = "Local data collection enumerated $($found.Count) synthetic test files successfully" }
} else {
  $res = @{ Outcome = 'error'; Reason = "Local data collection found $($found.Count) files, expected 3" }
}
Complete-CgStep $res 'COLL-01'
