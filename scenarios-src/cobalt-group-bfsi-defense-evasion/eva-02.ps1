# Cobalt Group BFSI - Security Tool Impairment Permission Probe (eva-02)
if (-not (Test-CgGate 'BAS_CONFIRM_DEFENSE_EVASION_PROBE')) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_DEFENSE_EVASION_PROBE gate not set; this probe is opt-in' } 'EVA-02'
}
$undo_data = @{ scenario = 'eva-02' }
try { New-CgUndoRecord 'eva-02' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'eva-02' }

try {
  $prefs = Get-MpPreference -ErrorAction Stop
  $res = @{ Outcome = 'fail'; Reason = "Current user could read Defender preferences (DisableRealtimeMonitoring=$($prefs.DisableRealtimeMonitoring)); this is a read-only probe, no setting was changed" }
} catch {
  $res = @{ Outcome = 'pass'; Reason = 'Current user could not read Defender preferences' }
}
Complete-CgStep $res 'EVA-02'
