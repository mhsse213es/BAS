# Cobalt Group BFSI - Registry Run Key Persistence (pers-01)
$valueName = $script:CgTag + '-run'
$undo_data = @{ scenario = 'pers-01'; valueName = $valueName }
try { New-CgUndoRecord 'pers-01' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'pers-01' }

$runPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
try {
  New-ItemProperty -Path $runPath -Name $valueName -Value 'powershell.exe -NoProfile -Command exit' -PropertyType String -Force -ErrorAction Stop | Out-Null
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not write Run key value: $($_.Exception.Message)" } 'pers-01'
}

if (Test-CgRunKeyExists -Name $valueName) {
  $res = @{ Outcome = 'pass'; Reason = 'Registry Run Key persistence value was created and confirmed present' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'Registry Run Key write did not take effect' }
}
Complete-CgStep $res 'pers-01'
