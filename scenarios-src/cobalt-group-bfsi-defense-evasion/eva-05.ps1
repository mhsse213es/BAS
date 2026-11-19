# Cobalt Group BFSI - Registry Modification Detection Test (eva-05)
$keyPath = 'HKCU:\Software\BAS-SIM-Test'
$undo_data = @{ scenario = 'eva-05'; keyPath = $keyPath }
try { New-CgUndoRecord 'eva-05' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'eva-05' }

try {
  New-Item -Path $keyPath -Force -ErrorAction Stop | Out-Null
  Set-ItemProperty -Path $keyPath -Name 'bas_sim_marker' -Value $script:CgTag -ErrorAction Stop
  $written = (Get-ItemProperty -Path $keyPath -Name 'bas_sim_marker' -ErrorAction Stop).bas_sim_marker -eq $script:CgTag
} catch { $written = $false }
Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue

if ($written) {
  $res = @{ Outcome = 'fail'; Reason = 'Synthetic registry value was written and read back without being blocked or flagged' }
} else {
  $res = @{ Outcome = 'pass'; Reason = 'Synthetic registry write was blocked' }
}
Complete-CgStep $res 'EVA-05'
