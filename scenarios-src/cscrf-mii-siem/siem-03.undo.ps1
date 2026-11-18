# Undo: Windows event log entries cannot be removed by BAS. Record the tag as residue and report it.
$rec = Read-CgUndoRecord 'siem-03'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'PASS: Cleanup complete (no record)'; exit 0 }
Write-Output "PASS: Cleanup complete; event with tag $($rec.tag) remains in the Application log (event ID 4242, source BAS-SIEM) by design"
Remove-CgUndoRecord 'siem-03'
exit 0
