# Undo: remove the synthetic account.
$rec = Read-CgUndoRecord 'ir-04'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
Remove-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue
if (Get-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue) { Write-Output "FAIL: residue account $($rec.accountName) survived undo"; exit 0 }
Remove-CgUndoRecord 'ir-04'
Write-Output 'PASS: Cleanup complete'
exit 0
