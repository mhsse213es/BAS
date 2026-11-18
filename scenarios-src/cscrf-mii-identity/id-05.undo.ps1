# Undo: disabled account logon attempt. Removes the synthetic account and its record.
$rec = Read-CgUndoRecord 'id-05'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
Remove-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue
if (Get-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue) { Write-Output "FAIL: residue account $($rec.accountName) survived undo"; exit 0 }
Remove-CgUndoRecord 'id-05'
Write-Output 'PASS: Cleanup complete'
exit 0
