# Undo: Event Log Clearing Attempt, Non-Destructive
# SAFETY: removes only the dedicated synthetic 'BAS-SIM-Test' log created by the step; never touches
# Security, System, Application, or any other real log.
$rec = Read-CgUndoRecord 'eva-06'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

if ($rec.logName -and $rec.logName -eq 'BAS-SIM-Test') {
  Remove-EventLog -LogName $rec.logName -ErrorAction SilentlyContinue
}
Remove-CgUndoRecord 'eva-06'
Write-Output 'PASS: Cleanup complete'
exit 0
