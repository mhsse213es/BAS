# Cobalt Group BFSI - Event Log Clearing Attempt, Non-Destructive (eva-06)
# SAFETY: this step only ever creates, writes to, and clears a dedicated synthetic log named
# 'BAS-SIM-Test'. It must never reference Security, System, Application, or any other real log.
$logName = 'BAS-SIM-Test'
$source = 'BAS-SIM-Test-Source'
$undo_data = @{ scenario = 'eva-06'; logName = $logName }
try { New-CgUndoRecord 'eva-06' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'eva-06' }

try {
  if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    New-EventLog -LogName $logName -Source $source -ErrorAction Stop
  }
  Write-EventLog -LogName $logName -Source $source -EventId 1 -Message ('BAS-SIM test entry ' + $script:CgTag) -ErrorAction Stop
  Clear-EventLog -LogName $logName -ErrorAction Stop
  $entries = Get-EventLog -LogName $logName -Newest 5 -ErrorAction SilentlyContinue
  $cleared = (-not $entries) -or ($entries.Count -eq 0)
  if ($cleared) {
    $res = @{ Outcome = 'fail'; Reason = "Synthetic test log '$logName' was cleared without being blocked or flagged" }
  } else {
    $res = @{ Outcome = 'error'; Reason = "Clear-EventLog on '$logName' did not report an error but entries remain" }
  }
} catch {
  $res = @{ Outcome = 'skip'; Reason = "Could not create/write/clear the dedicated '$logName' log on this host (likely requires elevation): $($_.Exception.Message)" }
}
Remove-EventLog -LogName $logName -ErrorAction SilentlyContinue
Complete-CgStep $res 'EVA-06'
