# Cobalt Group BFSI - Masquerading Executable Detection Test (eva-04)
$testDir = Join-Path $env:TEMP ('bas_sim_eva04_' + $script:CgRun)
$masqPath = Join-Path $testDir 'svchost_bas_sim_test.exe'
$undo_data = @{ scenario = 'eva-04'; testDir = $testDir; masqPath = $masqPath }
try { New-CgUndoRecord 'eva-04' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'eva-04' }

New-Item -ItemType Directory -Force -Path $testDir | Out-Null
Copy-Item -Path (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $masqPath -Force -ErrorAction SilentlyContinue
$copied = Test-Path -LiteralPath $masqPath

$proc = $null
if ($copied) {
  try { $proc = Start-Process -FilePath $masqPath -ArgumentList '/c', 'exit' -PassThru -WindowStyle Hidden -ErrorAction Stop; $proc.WaitForExit(5000) | Out-Null } catch {}
}
Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue

if ($copied -and $proc) {
  $res = @{ Outcome = 'fail'; Reason = 'Masquerading executable was copied and executed without being blocked or flagged' }
} elseif ($copied) {
  $res = @{ Outcome = 'pass'; Reason = 'Masquerading executable was copied but execution was blocked' }
} else {
  $res = @{ Outcome = 'pass'; Reason = 'Masquerading executable copy was blocked' }
}
Complete-CgStep $res 'EVA-04'
