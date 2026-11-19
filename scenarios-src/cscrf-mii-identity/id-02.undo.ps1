# Undo: local administrator account creation. Removes the synthetic account and its record.
$rec = Read-CgUndoRecord 'id-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $rec.accountName -ErrorAction SilentlyContinue
Remove-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue
if (Get-LocalUser -Name $rec.accountName -ErrorAction SilentlyContinue) { Write-Output "FAIL: residue account $($rec.accountName) survived undo"; exit 0 }
Remove-CgUndoRecord 'id-02'
Write-Output 'PASS: Cleanup complete'
exit 0
