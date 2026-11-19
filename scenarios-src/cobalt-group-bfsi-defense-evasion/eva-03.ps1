# Cobalt Group BFSI - PowerShell Obfuscation Detection Test (eva-03)
$marker = 'bas-sim-obfuscation-test-' + $script:CgRun
$undo_data = @{ scenario = 'eva-03'; marker = $marker }
try { New-CgUndoRecord 'eva-03' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'eva-03' }

$res = Invoke-EncodedCommandProbe -PlainText ("Write-Output '" + $marker + "'") -ExpectMarker $marker
Complete-CgStep $res 'EVA-03'
